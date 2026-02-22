package cli

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/daemon"
	"github.com/guras256/keenetic-split-tunnel/internal/deploy"
	"github.com/guras256/keenetic-split-tunnel/internal/group"
	"github.com/guras256/keenetic-split-tunnel/internal/healthcheck"
	"github.com/guras256/keenetic-split-tunnel/internal/platform"
	"github.com/guras256/keenetic-split-tunnel/internal/router"
	"github.com/guras256/keenetic-split-tunnel/internal/service"
)

func newSetupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "Interactive initial setup wizard",
		RunE: func(cmd *cobra.Command, args []string) error {
			reader := bufio.NewReader(os.Stdin)
			ctx := cmd.Context()

			fmt.Println("=== KST Setup ===")
			fmt.Println()

			// 1. Check dependencies.
			missing := deploy.CheckDependencies()
			if len(missing) > 0 {
				printFail("Dependencies: missing packages")
				var pkgs []string
				for _, m := range missing {
					fmt.Printf("      - %s (opkg: %s)\n", m.Dep.Name, m.Dep.Package)
					pkgs = append(pkgs, m.Dep.Package)
				}
				fmt.Println()
				answer := prompt(reader, "Install missing packages now? [y/N]", "n")
				if strings.ToLower(answer) == "y" {
					if err := deploy.InstallOpkgDeps(ctx, pkgs); err != nil {
						return fmt.Errorf("opkg install failed: %w\nInstall manually: opkg install %s", err, strings.Join(pkgs, " "))
					}
					printPass("Packages installed")
				} else {
					return fmt.Errorf("required packages not installed. Run: opkg install %s", strings.Join(pkgs, " "))
				}
			} else {
				printPass("Dependencies: all packages found")
			}

			// 1b. Check iptables TPROXY support (needed for UDP proxying).
			if !deploy.CheckIPTablesTproxy(ctx) {
				printWarn("TPROXY: not available (UDP proxying may not work)")
				answer := prompt(reader, "  Upgrade iptables now? [Y/n]", "y")
				if strings.ToLower(answer) != "n" {
					if err := deploy.UpgradeOpkgDeps(ctx, []string{"iptables"}); err != nil {
						printFail(fmt.Sprintf("TPROXY upgrade failed: %v", err))
					} else if deploy.CheckIPTablesTproxy(ctx) {
						printPass("TPROXY: available after upgrade")
					} else {
						printWarn("TPROXY: still not available after upgrade")
					}
				}
			} else {
				printPass("TPROXY: available")
			}

			// 2. Check dns-override (Keenetic must delegate DNS to Entware dnsmasq).
			rci := router.NewClient()
			dnsOverride, err := rci.IsDNSOverrideEnabled(ctx)
			if err != nil {
				printWarn(fmt.Sprintf("DNS override: could not check (%v)", err))
				fmt.Println("      Make sure dns-override is enabled: opkg dns-override && system configuration save")
			} else if !dnsOverride {
				printFail("DNS override: not enabled")
				answer := prompt(reader, "  Enable dns-override now? [Y/n]", "y")
				if strings.ToLower(answer) != "n" {
					if err := rci.EnableDNSOverride(ctx); err != nil {
						printFail(fmt.Sprintf("DNS override: failed to enable (%v)", err))
					} else {
						printPass("DNS override: enabled")
					}
				} else {
					printWarn("DNS override: skipped (enable manually later)")
				}
			} else {
				printPass("DNS override: enabled")
			}

			// 3. Create directories.
			if err := deploy.EnsureDirectories(); err != nil {
				return err
			}
			printPass("Directories: created")

			// Load existing config for defaults.
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			// 4. Routing mode selection.
			fmt.Println("Routing mode:")
			fmt.Println("  1) redirect  — TCP REDIRECT + UDP TPROXY to a local transparent proxy port")
			fmt.Println("               (ss-redir -u, xray dokodemo-door, sing-box, redsocks, …)")
			fmt.Println("  2) interface — MARK + policy routing via a VPN interface")
			fmt.Println("               (WireGuard wg0, OpenVPN tun0, …)")
			defaultModeIdx := 1
			if cfg.Routing.Mode == "interface" {
				defaultModeIdx = 2
			}
			modeStr := prompt(reader, fmt.Sprintf("  Pick mode [%d]", defaultModeIdx), "")
			switch modeStr {
			case "2", "interface":
				cfg.Routing.Mode = "interface"
			default:
				if modeStr == "" && defaultModeIdx == 2 {
					cfg.Routing.Mode = "interface"
				} else {
					cfg.Routing.Mode = "redirect"
				}
			}
			fmt.Printf("  Mode: %s\n", cfg.Routing.Mode)
			fmt.Println()

			// 5. Mode-specific configuration.
			switch cfg.Routing.Mode {
			case "interface":
				fmt.Println("VPN interface configuration:")
				fmt.Println("  Set up your VPN (WireGuard, OpenVPN, etc.) separately.")
				fmt.Println("  KST will route matched traffic via the specified interface.")
				cfg.Routing.Interface = prompt(reader, "  VPN interface name (e.g. wg0, tun0)", cfg.Routing.Interface)
				fmt.Println()
			default:
				fmt.Println("Transparent proxy configuration:")
				fmt.Println("  Set up your proxy (ss-redir, xray, etc.) separately.")
				fmt.Println("  KST will redirect matched TCP and UDP traffic to the specified port.")
				cfg.Routing.LocalPort = promptInt(reader, "  Local port your proxy listens on", cfg.Routing.LocalPort)
				fmt.Println()
			}

			// 6. DNS configuration (informational).
			fmt.Println("DNS configuration:")
			fmt.Printf("  DNS queries: dnsmasq -> dnscrypt-proxy (:%d) -> encrypted upstream\n", cfg.DNSCrypt.Port)
			fmt.Println()

			// 7. Network interface.
			fmt.Println("Network interface:")
			cfg.Network.EntwareInterface = promptInterface(reader, ctx, cfg.Network.EntwareInterface)
			fmt.Println()

			cfg.SetupFinished = true

			// 8. Save KST config.
			if err := config.Save(cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			printPass("Config saved")

			fmt.Println()

			// 9. Start dnscrypt-proxy.
			if err := service.DNSCrypt.EnsureRunning(ctx); err != nil {
				printFail(fmt.Sprintf("dnscrypt-proxy: %v", err))
			} else {
				printPass("dnscrypt-proxy: running")
			}

			// 10. Generate dnsmasq.conf and start dnsmasq.
			if err := deploy.WriteDnsmasqConf(cfg); err != nil {
				return fmt.Errorf("write dnsmasq.conf: %w", err)
			}
			printPass(fmt.Sprintf("dnsmasq.conf: written to %s", platform.DnsmasqConfFile))

			if err := service.Dnsmasq.Restart(ctx); err != nil {
				printFail(fmt.Sprintf("dnsmasq: %v", err))
				fmt.Println("      Ensure dns-override is enabled, then: /opt/etc/init.d/S56dnsmasq start")
			} else {
				printPass("dnsmasq: running")
			}

			// 11. Install NDM hooks.
			n, err := deploy.InstallNDMHooks()
			if err != nil {
				printFail(fmt.Sprintf("NDM hooks: %v", err))
			} else {
				printPass(fmt.Sprintf("NDM hooks: %d installed", n))
			}

			// 12. Install init.d script.
			if err := deploy.InstallInitScript(); err != nil {
				printFail(fmt.Sprintf("Init script: %v", err))
			} else {
				printPass(fmt.Sprintf("Init script: %s", platform.InitScript))
			}

			// 13. Create default group if needed.
			store := group.NewDefaultStore()
			if err := store.EnsureDefaultGroup(); err != nil {
				return err
			}

			// 13b. Add ifconfig.me to the default group for IP verification.
			if err := store.AddEntry(group.DefaultGroupName, "ifconfig.me"); err != nil {
				// Ignore "already exists" errors.
				if !strings.Contains(err.Error(), "already exists") {
					printFail(fmt.Sprintf("ifconfig.me: %v", err))
				}
			}

			// 14. Run initial reconcile.
			logger := platform.NewLogger(cfg.Daemon.LogLevel)
			r := daemon.NewReconciler(cfg, store, logger)
			if err := r.Reconcile(ctx); err != nil {
				printFail(fmt.Sprintf("Reconcile: %v", err))
				fmt.Println("      Retry with: kst reconcile")
			} else {
				printPass("Reconcile: done")
			}

			// 15. Start the KST daemon.
			if err := service.Daemon.Start(ctx); err != nil {
				printFail(fmt.Sprintf("KST daemon: %v", err))
				fmt.Println("      Start manually: /opt/etc/init.d/S96kst start")
			} else {
				printPass("KST daemon: started")
			}

			fmt.Println()
			fmt.Println("Health check:")
			results := healthcheck.RunChecks(ctx, cfg, store)
			PrintResults(results)

			// 16. Domain probe: verify ifconfig.me resolves through the pipeline.
			fmt.Println()
			fmt.Println("Domain probe: ifconfig.me")
			probe, err := healthcheck.ProbeDomain(ctx, cfg, "ifconfig.me")
			if err != nil {
				printFail(fmt.Sprintf("ifconfig.me: %v", err))
			} else if len(probe.IPs) == 0 {
				printFail("ifconfig.me: no IPs resolved")
			} else {
				for _, ip := range probe.IPs {
					if probe.InIPSet[ip] {
						printPass(fmt.Sprintf("%s in ipset", ip))
					} else {
						printFail(fmt.Sprintf("%s not in ipset", ip))
					}
				}
			}

			fmt.Println()
			fmt.Println("Verify your setup:")
			fmt.Println("  Open https://ifconfig.me in your browser.")
			fmt.Println("  You should see your VPN/proxy IP, not your real IP.")
			fmt.Println()
			fmt.Println("Next steps:")
			fmt.Printf("  Web UI: http://%s%s\n", interfaceIP(cfg.Network.EntwareInterface), cfg.Daemon.WebListen)
			fmt.Println("  CLI:    kst add <domain>")

			return nil
		},
	}
}

func prompt(reader *bufio.Reader, label, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", label, defaultVal)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal
	}
	return line
}

func promptInt(reader *bufio.Reader, label string, defaultVal int) int {
	s := prompt(reader, label, fmt.Sprintf("%d", defaultVal))
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return defaultVal
	}
	return n
}

// promptInterface lists available bridge interfaces and lets the user pick one.
// Falls back to a plain text prompt if interface detection fails.
func promptInterface(reader *bufio.Reader, ctx context.Context, defaultVal string) string {
	bridges := detectBridgeInterfaces(ctx)

	if len(bridges) == 0 {
		return prompt(reader, "  Entware interface (e.g., br0)", defaultVal)
	}

	// Ensure the current default is in the list, or prepend it.
	if defaultVal != "" {
		found := false
		for _, b := range bridges {
			if b == defaultVal {
				found = true
				break
			}
		}
		if !found {
			bridges = append([]string{defaultVal}, bridges...)
		}
	}

	fmt.Println("  Available bridge interfaces:")
	defaultIdx := 1
	for i, b := range bridges {
		marker := ""
		if b == defaultVal || (defaultVal == "" && i == 0) {
			marker = " (default)"
			defaultIdx = i + 1
		}
		fmt.Printf("    %d) %s%s\n", i+1, b, marker)
	}

	for {
		s := prompt(reader, fmt.Sprintf("  Pick interface [%d]", defaultIdx), "")
		if s == "" {
			return bridges[defaultIdx-1]
		}
		var n int
		if _, err := fmt.Sscanf(s, "%d", &n); err == nil && n >= 1 && n <= len(bridges) {
			return bridges[n-1]
		}
		// Accept a typed interface name directly.
		for _, b := range bridges {
			if b == s {
				return s
			}
		}
		fmt.Printf("  Invalid choice. Enter a number between 1 and %d.\n", len(bridges))
	}
}

// detectBridgeInterfaces returns bridge interface names (Linux system names, e.g., "br0").
// Tries the Keenetic RCI API first, then falls back to /sys/class/net/.
func detectBridgeInterfaces(ctx context.Context) []string {
	// Try RCI API.
	rci := router.NewClient()
	if ifaces, err := rci.GetInterfaces(ctx); err == nil {
		var bridges []string
		for _, iface := range ifaces {
			name := iface.SystemName
			if name == "" {
				name = iface.ID
			}
			if strings.HasPrefix(name, "br") {
				bridges = append(bridges, name)
			}
		}
		if len(bridges) > 0 {
			sort.Strings(bridges)
			return bridges
		}
	}

	// Fallback: scan /sys/class/net/ for br* entries.
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var bridges []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "br") {
			bridges = append(bridges, e.Name())
		}
	}
	sort.Strings(bridges)
	return bridges
}

// interfaceIP returns the first IPv4 address of the named network interface,
// or "<router-ip>" if it cannot be determined.
func interfaceIP(name string) string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "<router-ip>"
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "<router-ip>"
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "<router-ip>"
}
