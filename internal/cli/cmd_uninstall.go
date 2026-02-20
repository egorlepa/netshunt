package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/daemon"
	"github.com/guras256/keenetic-split-tunnel/internal/deploy"
	"github.com/guras256/keenetic-split-tunnel/internal/group"
	"github.com/guras256/keenetic-split-tunnel/internal/platform"
	"github.com/guras256/keenetic-split-tunnel/internal/router"
	"github.com/guras256/keenetic-split-tunnel/internal/service"
)

func newUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove all KST rules, configs, and scripts",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			cfg, err := config.Load()
			if err != nil {
				return err
			}

			// 1. Stop KST daemon.
			fmt.Println("Stopping KST daemon...")
			if err := service.Daemon.Stop(ctx); err != nil {
				fmt.Printf("  Warning: %v\n", err)
			}

			// 2. Stop ss-redir.
			fmt.Println("Stopping ss-redir...")
			if err := service.Shadowsocks.Stop(ctx); err != nil {
				fmt.Printf("  Warning: %v\n", err)
			}

			// 3. Stop dnscrypt-proxy.
			fmt.Println("Stopping dnscrypt-proxy...")
			if err := service.DNSCrypt.Stop(ctx); err != nil {
				fmt.Printf("  Warning: %v\n", err)
			}

			// 3. Remove iptables rules.
			fmt.Println("Removing iptables rules...")
			logger := platform.NewLogger("error")
			groups := group.NewDefaultStore()
			r := daemon.NewReconciler(cfg, groups, logger)
			if err := r.Mode.TeardownRules(ctx); err != nil {
				fmt.Printf("  Warning: %v\n", err)
			}

			// 4. Flush and destroy ipset table.
			fmt.Println("Removing ipset table...")
			_ = r.IPSet.Flush(ctx)
			_ = r.IPSet.Destroy(ctx)

			// 5. Stop dnsmasq (must be stopped before disabling dns-override).
			fmt.Println("Stopping dnsmasq...")
			if err := service.Dnsmasq.Stop(ctx); err != nil {
				fmt.Printf("  Warning: %v\n", err)
			}

			// 6. Disable dns-override so Keenetic reclaims DNS after reboot.
			fmt.Println("Disabling dns-override...")
			rci := router.NewClient()
			if err := rci.DisableDNSOverride(ctx); err != nil {
				fmt.Printf("  Warning: could not disable dns-override: %v\n", err)
				fmt.Println("  Disable manually: no opkg dns-override && system configuration save")
			}

			// 7. Remove dnsmasq config files.
			fmt.Println("Removing dnsmasq config...")
			_ = r.Dnsmasq.RemoveIPSetConfig()
			_ = os.Remove(platform.DnsmasqConfFile)

			// 8. Remove shadowsocks config.
			fmt.Println("Removing shadowsocks config...")
			_ = os.Remove(platform.ShadowsocksConfig)

			// 9. Remove init.d scripts.
			fmt.Println("Removing init.d scripts...")
			_ = os.Remove(platform.InitScript)
			_ = os.Remove(platform.SSRedirInitScript)

			// 10. Remove NDM hooks.
			fmt.Println("Removing NDM hooks...")
			deploy.UninstallNDMHooks()

			// 11. Remove KST config directory.
			fmt.Println("Removing configuration...")
			_ = os.Remove(platform.ConfigFile)
			_ = os.Remove(platform.GroupsFile)
			_ = os.Remove(platform.PidFile)
			_ = os.Remove(platform.ConfigDir)

			fmt.Println()
			fmt.Println("KST removed. Next steps:")
			fmt.Println("  opkg remove kst shadowsocks-libev-ss-redir dnsmasq-full dnscrypt-proxy2")
			return nil
		},
	}
}
