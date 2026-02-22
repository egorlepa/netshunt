package cli

import (
	"github.com/spf13/cobra"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/daemon"
	"github.com/egorlepa/netshunt/internal/group"
	"github.com/egorlepa/netshunt/internal/platform"
)

func newDaemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "Run the daemon that serves the web UI and reconciles routing state",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			logger := platform.NewLogger(cfg.Daemon.LogLevel)
			groups := group.NewDefaultStore()
			d := daemon.New(cfg, groups, logger, version)
			return d.Run(cmd.Context())
		},
	}
}
