package cli

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/daemon"
	"github.com/egorlepa/netshunt/internal/platform"
	"github.com/egorlepa/netshunt/internal/shunt"
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

			var logOut []io.Writer
			fileLog, logErr := platform.OpenFileLog(platform.LogFile)
			if logErr == nil {
				defer fileLog.Close()
				logOut = append(logOut, fileLog)
			}
			var sys *platform.Syslog
			if cfg.Daemon.Syslog {
				sys = platform.OpenSyslog()
				defer sys.Close()
			}
			logger, logBuf := platform.NewDaemonLogger(cfg.Daemon.LogLevel, sys, logOut...)
			platform.RouteStdLog(logger)
			if logErr != nil {
				logger.Warn("log file unavailable, logging to web UI buffer only", "path", platform.LogFile, "error", logErr)
			}
			shunts := shunt.NewDefaultStore()
			d, err := daemon.New(cfg, shunts, logger, logBuf, version)
			if err != nil {
				return err
			}
			return d.Run(cmd.Context())
		},
	}
}
