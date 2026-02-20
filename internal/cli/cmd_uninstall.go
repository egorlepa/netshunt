package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/daemon"
	"github.com/guras256/keenetic-split-tunnel/internal/group"
	"github.com/guras256/keenetic-split-tunnel/internal/platform"
)

func newUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove all KST rules and configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			ctx := cmd.Context()
			logger := platform.NewLogger(cfg.Daemon.LogLevel)
			groups := group.NewDefaultStore()
			r := daemon.NewReconciler(cfg, groups, logger)

			// Teardown iptables rules.
			fmt.Println("Removing iptables rules...")
			if err := r.Mode.TeardownRules(ctx); err != nil {
				fmt.Printf("  Warning: %v\n", err)
			}

			// Flush and destroy ipset table.
			fmt.Println("Removing ipset table...")
			_ = r.IPSet.Flush(ctx)
			_ = r.IPSet.Destroy(ctx)

			// Remove dnsmasq ipset config.
			fmt.Println("Removing dnsmasq config...")
			_ = r.Dnsmasq.RemoveIPSetConfig()

			// Remove config and groups files.
			fmt.Println("Removing configuration...")
			_ = os.Remove(platform.ConfigFile)
			_ = os.Remove(platform.GroupsFile)
			_ = os.Remove(platform.PidFile)

			fmt.Println("Uninstall complete.")
			fmt.Println("You may also want to remove the binary and NDM scripts manually.")
			return nil
		},
	}
}
