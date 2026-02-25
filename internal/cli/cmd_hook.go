package cli

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/routing"
)

func newHookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "hook",
		Short:  "Handle NDM events (called by shell scripts, not user-facing)",
		Hidden: true,
	}

	cmd.AddCommand(
		newHookFsCmd(),
		newHookNetfilterCmd(),
		newHookIfstateCmd(),
		newHookWanCmd(),
	)

	return cmd
}

func hookLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// hook fs start — create ipset table on filesystem mount.
func newHookFsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fs <start|stop>",
		Short: "Filesystem mount event",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[0] != "start" {
				return nil
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			ipset := netfilter.NewIPSet(cfg.IPSet.TableName)
			return ipset.EnsureTable(cmd.Context())
		},
	}
}

// hook netfilter — iptables rules need to be (re)applied.
func newHookNetfilterCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "netfilter <type> <table>",
		Short: "Netfilter event",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			logger := hookLogger()
			mode := routing.New(cfg, logger)
			return mode.SetupRules(cmd.Context())
		},
	}
}

// hook ifstate — interface state change.
func newHookIfstateCmd() *cobra.Command {
	var id, systemName, connected, link, up string

	cmd := &cobra.Command{
		Use:   "ifstate",
		Short: "Interface state change event",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			// NDM passes the Linux system name as --system-name (or SYSTEM_NAME env).
			name := systemName
			if name == "" {
				name = os.Getenv("SYSTEM_NAME")
			}
			if name == "" {
				name = id // last-resort fallback
			}

			if name != cfg.Network.EntwareInterface {
				return nil
			}

			logger := hookLogger()
			mode := routing.New(cfg, logger)

			if connected == "yes" && link == "up" {
				logger.Info("interface up, setting up rules", "system-name", name)
				return mode.SetupRules(cmd.Context())
			}

			if link == "down" {
				logger.Info("interface down, tearing down rules", "system-name", name)
				return mode.TeardownRules(cmd.Context())
			}

			_ = up // available for future use
			return nil
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "Keenetic logical interface id")
	cmd.Flags().StringVar(&systemName, "system-name", "", "Linux interface name (e.g., br0)")
	cmd.Flags().StringVar(&connected, "connected", "", "connection state")
	cmd.Flags().StringVar(&link, "link", "", "link state")
	cmd.Flags().StringVar(&up, "up", "", "up state")
	return cmd
}

// hook wan — WAN connectivity event. Delegates reconcile to the daemon via HTTP API.
func newHookWanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "wan <start|stop>",
		Short: "WAN connectivity event",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			action := ""
			if len(args) > 0 {
				action = args[0]
			}
			if action == "stop" {
				return nil
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}

			apiURL := fmt.Sprintf("http://127.0.0.1%s/actions/reconcile", cfg.Daemon.WebListen)
			resp, err := http.Post(apiURL, "", nil)
			if err != nil {
				hookLogger().Warn("daemon not reachable, skipping reconcile", "error", err)
				return nil
			}
			resp.Body.Close()
			return nil
		},
	}
}
