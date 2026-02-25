package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	intdns "github.com/egorlepa/netshunt/internal/dns"
)

func newDNSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "DNS diagnostics",
	}

	cmd.AddCommand(
		newDNSTestCmd(),
		newDNSCryptStatusCmd(),
	)

	return cmd
}

func newDNSTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test [domain]",
		Short: "Test DNS resolution via local forwarder",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := "example.com"
			if len(args) > 0 {
				domain = args[0]
			}

			resolver := intdns.NewResolver("127.0.0.1")
			fmt.Printf("Resolving %s via 127.0.0.1 (forwarder)...\n", domain)
			ips, err := resolver.ResolveToStrings(cmd.Context(), domain)
			if err != nil {
				fmt.Printf("  Error: %v\n", err)
			} else {
				for _, ip := range ips {
					fmt.Printf("  %s\n", ip)
				}
			}

			return nil
		},
	}
}

func newDNSCryptStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "crypt-status",
		Short: "Show dnscrypt-proxy status",
		RunE: func(cmd *cobra.Command, args []string) error {
			d := intdns.NewDNSCrypt()

			fmt.Println("dnscrypt-proxy:")
			fmt.Printf("  Installed: %v\n", d.IsInstalled())
			fmt.Printf("  Running:   %v\n", d.IsRunning(cmd.Context()))
			return nil
		},
	}
}
