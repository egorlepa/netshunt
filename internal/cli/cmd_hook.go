package cli

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

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

// hookLogger logs to stderr at warn level; NETSHUNT_HOOK_LOG=info (or
// debug) lowers it, e.g. to see the rule changes a hook makes when run by
// hand.
func hookLogger() *slog.Logger {
	level := slog.LevelWarn
	if v := os.Getenv("NETSHUNT_HOOK_LOG"); v != "" {
		_ = level.UnmarshalText([]byte(v))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// hook fs start - create ipset table on filesystem mount.
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
			ctx := cmd.Context()
			return netfilter.NewIPSet(cfg.IPSet.TableName).EnsureTable(ctx)
		},
	}
}

// hook netfilter - iptables rules need to be (re)applied.
func newHookNetfilterCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "netfilter <type> <table>",
		Short: "Netfilter event",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// NDM rebuilt one of its tables. netshunt only manages IPv4
			// nat/mangle rules; Reconcile reads both and fixes what is
			// missing, and only reads when nothing is.
			if args[0] != "iptables" {
				return nil
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			logger := hookLogger()
			mode := routing.New(config.NewLive(cfg), logger)
			return mode.Reconcile(cmd.Context())
		},
	}
}

// ifstateEvent is one NDM ifstatechanged call.
type ifstateEvent struct {
	id, systemName, connected, link, up string
}

// name returns the Linux interface name. NDM sets system_name in the
// environment; the script passes it as --system-name.
func (e ifstateEvent) name() string {
	for _, n := range []string{e.systemName, os.Getenv("system_name"), os.Getenv("SYSTEM_NAME"), e.id} {
		if n != "" {
			return n
		}
	}
	return ""
}

// shouldReconcile reports whether the event needs the rules converged: an
// up/connected event on an interface netshunt intercepts. Link down does
// nothing: rules with -i on an absent interface match no packets, and
// removing them would only open a window when it comes back.
func (e ifstateEvent) shouldReconcile(cfg *config.Config) bool {
	if e.link == "down" {
		return false
	}
	if e.link != "up" && e.connected != "yes" && e.up != "up" {
		return false
	}
	name := e.name()
	for _, iface := range cfg.Network.InterceptInterfaces() {
		if name == iface {
			return true
		}
	}
	return false
}

// hook ifstate - interface state change.
func newHookIfstateCmd() *cobra.Command {
	var ev ifstateEvent

	cmd := &cobra.Command{
		Use:   "ifstate",
		Short: "Interface state change event",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if !ev.shouldReconcile(cfg) {
				return nil
			}
			logger := hookLogger()
			logger.Info("managed interface up, reconciling rules", "system-name", ev.name())
			return routing.New(config.NewLive(cfg), logger).Reconcile(cmd.Context())
		},
	}

	cmd.Flags().StringVar(&ev.id, "id", "", "Keenetic logical interface id")
	cmd.Flags().StringVar(&ev.systemName, "system-name", "", "Linux interface name (e.g., br0)")
	cmd.Flags().StringVar(&ev.connected, "connected", "", "connection state")
	cmd.Flags().StringVar(&ev.link, "link", "", "link state")
	cmd.Flags().StringVar(&ev.up, "up", "", "up state")
	return cmd
}

// hook wan - WAN connectivity event. Delegates reconcile to the daemon via HTTP API.
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
			// The daemon finishes the reconcile even if we give up waiting:
			// the request context is detached server-side. The timeout only
			// keeps a wedged daemon from hanging the NDM hook forever.
			client := &http.Client{Timeout: 5 * time.Minute}
			resp, err := client.Post(apiURL, "", nil)
			if err != nil {
				hookLogger().Warn("daemon not reachable, skipping reconcile", "error", err)
				return nil
			}
			_ = resp.Body.Close()
			return nil
		},
	}
}
