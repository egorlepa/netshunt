package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/daemon"
	"github.com/guras256/keenetic-split-tunnel/internal/deploy"
	"github.com/guras256/keenetic-split-tunnel/internal/group"
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
			fmt.Println("Checking dependencies...")
			missing := deploy.CheckDependencies()
			if len(missing) > 0 {
				fmt.Println("  Missing required packages:")
				var pkgs []string
				for _, m := range missing {
					fmt.Printf("    - %s (opkg: %s)\n", m.Dep.Name, m.Dep.Package)
					pkgs = append(pkgs, m.Dep.Package)
				}
				fmt.Println()
				answer := prompt(reader, "Install missing packages now? [y/N]", "n")
				if strings.ToLower(answer) == "y" {
					fmt.Println("Running opkg install...")
					if err := deploy.InstallOpkgDeps(ctx, pkgs); err != nil {
						return fmt.Errorf("opkg install failed: %w\nInstall manually: opkg install %s", err, strings.Join(pkgs, " "))
					}
					fmt.Println("  Packages installed.")
				} else {
					return fmt.Errorf("required packages not installed. Run: opkg install %s", strings.Join(pkgs, " "))
				}
			} else {
				fmt.Println("  All required packages found.")
			}
			fmt.Println()

			// 2. Check dns-override (Keenetic must delegate DNS to Entware dnsmasq).
			fmt.Println("Checking DNS override...")
			rci := router.NewClient()
			dnsOverride, err := rci.IsDNSOverrideEnabled(ctx)
			if err != nil {
				fmt.Printf("  Warning: could not check dns-override: %v\n", err)
				fmt.Println("  Make sure dns-override is enabled in the router CLI:")
				fmt.Println("    opkg dns-override")
				fmt.Println("    system configuration save")
			} else if !dnsOverride {
				fmt.Println("  dns-override is NOT enabled.")
				fmt.Println("  KST needs to take over DNS (port 53) from the router's built-in DNS.")
				answer := prompt(reader, "Enable dns-override now? [Y/n]", "y")
				if strings.ToLower(answer) != "n" {
					if err := rci.EnableDNSOverride(ctx); err != nil {
						fmt.Printf("  Warning: failed to enable dns-override: %v\n", err)
						fmt.Println("  Enable manually in the router CLI:")
						fmt.Println("    opkg dns-override")
						fmt.Println("    system configuration save")
					} else {
						fmt.Println("  dns-override enabled and config saved.")
					}
				} else {
					fmt.Println("  Warning: without dns-override, dnsmasq will conflict with the built-in DNS.")
					fmt.Println("  Enable it manually later: opkg dns-override && system configuration save")
				}
			} else {
				fmt.Println("  dns-override is enabled.")
			}
			fmt.Println()

			// 3. Create directories.
			if err := deploy.EnsureDirectories(); err != nil {
				return err
			}

			// 3. Load or create config.
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			// 4. Shadowsocks configuration.
			fmt.Println("Shadowsocks configuration:")
			cfg.Shadowsocks.Server = prompt(reader, "  Server address", cfg.Shadowsocks.Server)
			cfg.Shadowsocks.ServerPort = promptInt(reader, "  Server port", cfg.Shadowsocks.ServerPort)
			cfg.Shadowsocks.LocalPort = promptInt(reader, "  Local port", cfg.Shadowsocks.LocalPort)
			cfg.Shadowsocks.Password = prompt(reader, "  Password", cfg.Shadowsocks.Password)
			cfg.Shadowsocks.Method = prompt(reader, "  Encryption method", cfg.Shadowsocks.Method)
			fmt.Println()

			if err := deploy.ValidateShadowsocksConfig(cfg); err != nil {
				return fmt.Errorf("invalid config: %w", err)
			}

			// 5. DNS configuration.
			fmt.Println("DNS configuration:")
			fmt.Printf("  DNS queries: dnsmasq -> dnscrypt-proxy (:%d) -> encrypted upstream\n", cfg.DNSCrypt.Port)
			fmt.Println()

			// 6. Network interface.
			fmt.Println("Network interface:")
			cfg.Network.EntwareInterface = promptInterface(reader, ctx, cfg.Network.EntwareInterface)
			fmt.Println()

			cfg.SetupFinished = true

			// 7. Save KST config.
			if err := config.Save(cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			fmt.Println("Config saved.")

			// 8. Generate shadowsocks.json and start ss-redir.
			fmt.Println("Generating shadowsocks.json...")
			if err := deploy.WriteShadowsocksConfig(cfg); err != nil {
				return fmt.Errorf("write shadowsocks.json: %w", err)
			}
			fmt.Printf("  Written to %s\n", platform.ShadowsocksConfig)

			fmt.Println("Installing ss-redir init script...")
			if err := deploy.InstallSSRedirInitScript(); err != nil {
				fmt.Printf("  Warning: %v\n", err)
			} else {
				fmt.Printf("  Installed %s\n", platform.SSRedirInitScript)
			}

			fmt.Println("Starting ss-redir...")
			if err := service.Shadowsocks.EnsureRunning(ctx); err != nil {
				fmt.Printf("  Warning: %v\n", err)
				fmt.Println("  ss-redir must be running for tunnel to work.")
				fmt.Println("  Install: opkg install shadowsocks-libev-ss-redir")
			} else {
				fmt.Println("  ss-redir is running.")
			}

			fmt.Println("Starting dnscrypt-proxy2...")
			if err := service.DNSCrypt.EnsureRunning(ctx); err != nil {
				fmt.Printf("  Warning: %v\n", err)
			} else {
				fmt.Println("  dnscrypt-proxy2 is running.")
			}

			// 9. Generate dnsmasq.conf and start dnsmasq.
			fmt.Println("Generating dnsmasq.conf...")
			if err := deploy.WriteDnsmasqConf(cfg); err != nil {
				return fmt.Errorf("write dnsmasq.conf: %w", err)
			}
			fmt.Printf("  Written to %s\n", platform.DnsmasqConfFile)

			fmt.Println("Starting dnsmasq...")
			if err := service.Dnsmasq.Restart(ctx); err != nil {
				fmt.Printf("  Warning: failed to start dnsmasq: %v\n", err)
				fmt.Println("  Port 53 may still be held by Keenetic's built-in DNS.")
				fmt.Println("  Ensure dns-override is enabled, then start manually:")
				fmt.Println("    /opt/etc/init.d/S56dnsmasq start")
			} else {
				fmt.Println("  dnsmasq is running.")
			}

			// 10. Install NDM hooks.
			fmt.Println("Installing NDM hooks...")
			n, err := deploy.InstallNDMHooks()
			if err != nil {
				fmt.Printf("  Warning: %v\n", err)
			} else {
				fmt.Printf("  Installed %d hooks.\n", n)
			}

			// 11. Install init.d script.
			fmt.Println("Installing init.d script...")
			if err := deploy.InstallInitScript(); err != nil {
				fmt.Printf("  Warning: %v\n", err)
			} else {
				fmt.Printf("  Installed %s\n", platform.InitScript)
			}

			// 12. Create default group if needed.
			store := group.NewDefaultStore()
			if err := store.EnsureDefaultGroup(); err != nil {
				return err
			}

			// 13. Run initial reconcile.
			fmt.Println()
			fmt.Println("Running initial reconcile...")
			logger := platform.NewLogger(cfg.Daemon.LogLevel)
			r := daemon.NewReconciler(cfg, store, logger)
			if err := r.Reconcile(ctx); err != nil {
				fmt.Printf("Warning: initial reconcile failed: %v\n", err)
				fmt.Println("You can retry with: kst apply")
			} else {
				fmt.Println("Setup complete!")
			}

			// 14. Start the KST daemon.
			fmt.Println("Starting KST daemon...")
			if err := service.Daemon.Start(ctx); err != nil {
				fmt.Printf("  Warning: %v\n", err)
				fmt.Println("  Start manually: /opt/etc/init.d/S96kst start")
			} else {
				fmt.Println("  KST daemon started.")
			}

			fmt.Println()
			printServiceStatus(ctx)

			if !service.Shadowsocks.IsRunning(ctx) {
				fmt.Println()
				fmt.Println("WARNING: ss-redir is not running. The tunnel will NOT work.")
				fmt.Println("  Check: opkg install shadowsocks-libev-ss-redir")
			}

			fmt.Println()
			fmt.Println("Next steps:")
			fmt.Println("  kst add youtube.com   # add a domain")

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
