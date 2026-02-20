package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/daemon"
	"github.com/guras256/keenetic-split-tunnel/internal/group"
	"github.com/guras256/keenetic-split-tunnel/internal/platform"
	"github.com/guras256/keenetic-split-tunnel/internal/service"
)

func newSSRCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssr",
		Short: "Manage Shadowsocks",
	}

	cmd.AddCommand(
		newSSRStatusCmd(),
		newSSRPortCmd(),
		newSSRResetCmd(),
	)

	return cmd
}

func newSSRStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show Shadowsocks status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			ctx := cmd.Context()
			installed := service.Shadowsocks.IsInstalled()
			running := false
			if installed {
				running = service.Shadowsocks.IsRunning(ctx)
			}

			fmt.Println("Shadowsocks:")
			fmt.Printf("  Installed:  %v\n", installed)
			fmt.Printf("  Running:    %v\n", running)
			fmt.Printf("  Server:     %s:%d\n", cfg.Shadowsocks.Server, cfg.Shadowsocks.ServerPort)
			fmt.Printf("  Local port: %d\n", cfg.Shadowsocks.LocalPort)
			fmt.Printf("  Method:     %s\n", cfg.Shadowsocks.Method)
			return nil
		},
	}
}

func newSSRPortCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "port <port>",
		Short: "Change Shadowsocks local port",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var port int
			if _, err := fmt.Sscanf(args[0], "%d", &port); err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("invalid port: %s", args[0])
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}

			cfg.Shadowsocks.LocalPort = port
			if err := config.Save(cfg); err != nil {
				return err
			}

			fmt.Printf("Shadowsocks local port changed to %d\n", port)
			fmt.Println("Run 'kst update' to apply changes.")
			return nil
		},
	}
}

func newSSRResetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset",
		Short: "Reset Shadowsocks iptables rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			logger := platform.NewLogger(cfg.Daemon.LogLevel)
			groups := group.NewDefaultStore()
			r := daemon.NewReconciler(cfg, groups, logger)

			ctx := cmd.Context()
			if err := r.Mode.TeardownRules(ctx); err != nil {
				return fmt.Errorf("teardown: %w", err)
			}
			if err := r.Mode.SetupRules(ctx); err != nil {
				return fmt.Errorf("setup: %w", err)
			}

			fmt.Println("Shadowsocks iptables rules reset.")
			return nil
		},
	}
}
