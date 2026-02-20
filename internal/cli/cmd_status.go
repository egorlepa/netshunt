package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/group"
	"github.com/guras256/keenetic-split-tunnel/internal/netfilter"
	"github.com/guras256/keenetic-split-tunnel/internal/service"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show system status and diagnostics",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			fmt.Println("=== KST Status ===")
			fmt.Println()

			printServiceStatus(ctx)
			fmt.Println()
			printIPSetStatus(ctx, cfg)
			fmt.Println()
			printGroupStatus(cfg)
			fmt.Println()
			printConfigSummary(cfg)

			return nil
		},
	}
}

func printServiceStatus(ctx context.Context) {
	fmt.Println("Services:")
	services := []service.Service{
		service.Dnsmasq,
		service.DNSCrypt,
		service.Shadowsocks,
		service.Daemon,
	}
	for _, svc := range services {
		status := "not installed"
		if svc.IsInstalled() {
			if svc.IsRunning(ctx) {
				status = "running"
			} else {
				status = "stopped"
			}
		}
		fmt.Printf("  %-25s %s\n", svc.Name, status)
	}
}

func printIPSetStatus(ctx context.Context, cfg *config.Config) {
	ipset := netfilter.NewIPSet(cfg.IPSet.TableName)
	count, err := ipset.Count(ctx)
	if err != nil {
		fmt.Printf("IPSet table %q: error (%v)\n", cfg.IPSet.TableName, err)
		return
	}
	fmt.Printf("IPSet table %q: %d entries\n", cfg.IPSet.TableName, count)
}

func printGroupStatus(cfg *config.Config) {
	store := group.NewDefaultStore()
	groups, err := store.List()
	if err != nil {
		fmt.Printf("Groups: error (%v)\n", err)
		return
	}

	enabled, total := 0, 0
	entryCount := 0
	for _, g := range groups {
		total++
		if g.Enabled {
			enabled++
			entryCount += len(g.Entries)
		}
	}
	fmt.Printf("Groups: %d/%d enabled, %d total entries\n", enabled, total, entryCount)
}

func printConfigSummary(cfg *config.Config) {
	fmt.Println("Config:")
	fmt.Printf("  Mode:          %s\n", cfg.Mode)
	fmt.Printf("  SS local port: %d\n", cfg.Shadowsocks.LocalPort)
	fmt.Printf("  DNSCrypt port: %d\n", cfg.DNSCrypt.Port)
	fmt.Printf("  Web UI:        %s\n", cfg.Daemon.WebListen)
}
