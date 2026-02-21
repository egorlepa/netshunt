package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/netfilter"
	"github.com/guras256/keenetic-split-tunnel/internal/platform"
	"github.com/guras256/keenetic-split-tunnel/internal/service"
)

func newDebugCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "debug",
		Short: "Dump diagnostic information for troubleshooting",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			fmt.Println("=== KST Debug ===")
			fmt.Printf("Version: %s\n\n", version)

			debugServices(ctx)
			debugIPSet(ctx, cfg)
			debugIPTables(ctx)
			debugDnsmasqConfig()
			debugConfig(cfg)

			return nil
		},
	}
}

func debugServices(ctx context.Context) {
	fmt.Println("--- Services ---")
	for _, svc := range []service.Service{service.Dnsmasq, service.DNSCrypt, service.Daemon} {
		installed := svc.IsInstalled()
		running := false
		if installed {
			running = svc.IsRunning(ctx)
		}
		fmt.Printf("%-25s installed=%-5v running=%v\n", svc.Name, installed, running)
	}
	fmt.Println()
}

func debugIPSet(ctx context.Context, cfg *config.Config) {
	fmt.Println("--- IPSet ---")
	ipset := netfilter.NewIPSet(cfg.IPSet.TableName)
	entries, err := ipset.List(ctx)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Table %q: %d entries\n", cfg.IPSet.TableName, len(entries))
		for _, e := range entries {
			fmt.Printf("  %s\n", e)
		}
	}
	fmt.Println()
}

func debugIPTables(ctx context.Context) {
	fmt.Println("--- IPTables NAT ---")
	out, err := platform.Run(ctx, "iptables", "-t", "nat", "-L", "-n", "--line-numbers")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println(out)
	}
	fmt.Println()
}

func debugDnsmasqConfig() {
	fmt.Println("--- dnsmasq ipset config ---")
	data, err := os.ReadFile(platform.DnsmasqIPSetFile)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Print(string(data))
	}
	fmt.Println()
}

func debugConfig(cfg *config.Config) {
	fmt.Println("--- Config ---")
	fmt.Printf("Proxy type:        %s\n", cfg.Proxy.Type)
	switch cfg.Proxy.Type {
	case "tun":
		fmt.Printf("Proxy interface:   %s\n", cfg.Proxy.Interface)
	default:
		fmt.Printf("Proxy port:        %d\n", cfg.Proxy.LocalPort)
	}
	fmt.Printf("DNSCrypt port:     %d\n", cfg.DNSCrypt.Port)
	fmt.Printf("Interface:         %s\n", cfg.Network.EntwareInterface)
	fmt.Printf("Web listen:        %s\n", cfg.Daemon.WebListen)
	fmt.Printf("Setup finished:    %v\n", cfg.SetupFinished)
	fmt.Println()
}
