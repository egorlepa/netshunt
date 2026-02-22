package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/daemon"
	"github.com/egorlepa/netshunt/internal/group"
	"github.com/egorlepa/netshunt/internal/platform"
)

func newReconcileCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reconcile",
		Short: "Reconcile current groups and config (ipset, iptables, dnsmasq)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			logger := platform.NewLogger(cfg.Daemon.LogLevel)
			groups := group.NewDefaultStore()
			r := daemon.NewReconciler(cfg, groups, logger)

			if err := r.Reconcile(cmd.Context()); err != nil {
				return err
			}

			fmt.Println("Reconcile complete.")
			return nil
		},
	}
}
