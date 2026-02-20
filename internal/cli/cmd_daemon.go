package cli

import (
	"github.com/spf13/cobra"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/daemon"
	"github.com/guras256/keenetic-split-tunnel/internal/group"
	"github.com/guras256/keenetic-split-tunnel/internal/platform"
)

func newDaemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "Start the long-running daemon (web UI + periodic refresh)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			logger := platform.NewLogger(cfg.Daemon.LogLevel)
			groups := group.NewDefaultStore()
			d := daemon.New(cfg, groups, logger)
			return d.Run(cmd.Context())
		},
	}
}
