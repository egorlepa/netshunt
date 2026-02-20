package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/daemon"
	"github.com/guras256/keenetic-split-tunnel/internal/group"
	"github.com/guras256/keenetic-split-tunnel/internal/netfilter"
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
		newHookDNSLocalCmd(),
		newHookIfstateCmd(),
		newHookWanCmd(),
		newHookIfaceCreatedCmd(),
		newHookIfaceDestroyedCmd(),
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
			groups := group.NewDefaultStore()
			r := daemon.NewReconciler(cfg, groups, logger)
			return r.Mode.SetupRules(cmd.Context())
		},
	}
}

// hook dns-local — redirect all DNS (port 53) traffic to local dnsmasq.
func newHookDNSLocalCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dns-local <type> <table>",
		Short: "DNS local redirect event",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			ctx := cmd.Context()
			ipt := netfilter.NewIPTables()
			iface := cfg.Network.EntwareInterface
			if iface == "" {
				iface = "br0"
			}

			// Check if DNS DNAT rule already exists.
			if ipt.RuleExists(ctx, "nat", "PREROUTING",
				"-i", iface, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to", "127.0.0.1") {
				return nil
			}

			// Redirect UDP and TCP port 53 to local dnsmasq.
			if err := ipt.AppendRule(ctx, "nat", "PREROUTING",
				"-i", iface, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to", "127.0.0.1"); err != nil {
				return fmt.Errorf("dns dnat udp: %w", err)
			}
			if err := ipt.AppendRule(ctx, "nat", "PREROUTING",
				"-i", iface, "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to", "127.0.0.1"); err != nil {
				return fmt.Errorf("dns dnat tcp: %w", err)
			}

			return nil
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
			// EntwareInterface is stored as the Linux name (e.g., "br0"), not the
			// Keenetic logical ID (e.g., "Bridge0") that --id carries.
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
			groups := group.NewDefaultStore()
			r := daemon.NewReconciler(cfg, groups, logger)

			if connected == "yes" && link == "up" {
				logger.Info("interface up, setting up rules", "system-name", name)
				return r.Mode.SetupRules(cmd.Context())
			}

			if link == "down" {
				logger.Info("interface down, tearing down rules", "system-name", name)
				return r.Mode.TeardownRules(cmd.Context())
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

// hook wan — WAN connectivity event.
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

			// On WAN up, do a full reconcile.
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			logger := hookLogger()
			groups := group.NewDefaultStore()
			r := daemon.NewReconciler(cfg, groups, logger)
			return r.Reconcile(cmd.Context())
		},
	}
}

// hook iface-created — new interface appeared.
func newHookIfaceCreatedCmd() *cobra.Command {
	var id, systemName string
	cmd := &cobra.Command{
		Use:   "iface-created",
		Short: "Interface created event",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Log for now; can be extended to auto-detect new VPN interfaces.
			if id != "" {
				fmt.Fprintf(os.Stderr, "interface created: id=%s system-name=%s\n", id, systemName)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "interface id")
	cmd.Flags().StringVar(&systemName, "system-name", "", "system interface name")
	return cmd
}

// hook iface-destroyed — interface removed.
func newHookIfaceDestroyedCmd() *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "iface-destroyed",
		Short: "Interface destroyed event",
		RunE: func(cmd *cobra.Command, args []string) error {
			if id != "" {
				fmt.Fprintf(os.Stderr, "interface destroyed: id=%s\n", id)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "interface id")
	return cmd
}
