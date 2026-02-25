package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/deploy"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/platform"
	"github.com/egorlepa/netshunt/internal/router"
	"github.com/egorlepa/netshunt/internal/routing"
	"github.com/egorlepa/netshunt/internal/service"
)

func newUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove all netshunt rules, configs, and scripts",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			cfg, err := config.Load()
			if err != nil {
				return err
			}

			// 1. Stop netshunt daemon (stops DNS forwarder + web UI).
			fmt.Println("Stopping netshunt daemon...")
			if err := service.Daemon.Stop(ctx); err != nil {
				fmt.Printf("  Warning: %v\n", err)
			}

			// 2. Stop dnscrypt-proxy.
			fmt.Println("Stopping dnscrypt-proxy...")
			if err := service.DNSCrypt.Stop(ctx); err != nil {
				fmt.Printf("  Warning: %v\n", err)
			}

			// 3. Remove iptables rules.
			fmt.Println("Removing iptables rules...")
			logger, _ := platform.NewLogger("error")
			mode := routing.New(cfg, logger)
			if err := mode.TeardownRules(ctx); err != nil {
				fmt.Printf("  Warning: %v\n", err)
			}

			// 4. Flush and destroy ipset table.
			fmt.Println("Removing ipset table...")
			ipset := netfilter.NewIPSet(cfg.IPSet.TableName)
			_ = ipset.Flush(ctx)
			_ = ipset.Destroy(ctx)

			// 5. Disable dns-override so Keenetic reclaims DNS after reboot.
			fmt.Println("Disabling dns-override...")
			rci := router.NewClient()
			if err := rci.DisableDNSOverride(ctx); err != nil {
				fmt.Printf("  Warning: could not disable dns-override: %v\n", err)
				fmt.Println("  Disable manually: no opkg dns-override && system configuration save")
			}

			// 6. Remove init.d scripts.
			fmt.Println("Removing init.d scripts...")
			_ = os.Remove(platform.InitScript)

			// 7. Remove NDM hooks.
			fmt.Println("Removing NDM hooks...")
			deploy.UninstallNDMHooks()

			// 8. Remove netshunt config (keep shunts for reinstall).
			fmt.Println("Removing configuration (keeping shunts)...")
			_ = os.Remove(platform.ConfigFile)
			_ = os.Remove(platform.PidFile)

			fmt.Println()
			fmt.Println("netshunt removed. Shunts preserved in " + platform.ShuntsFile)
			fmt.Println("Next steps:")
			fmt.Println("  opkg remove netshunt dnscrypt-proxy2")
			return nil
		},
	}
}
