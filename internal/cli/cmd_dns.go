package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	intdns "github.com/guras256/keenetic-split-tunnel/internal/dns"
)

func newDNSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "Manage DNS settings",
	}

	cmd.AddCommand(
		newDNSTestCmd(),
		newDNSCryptOnCmd(),
		newDNSCryptOffCmd(),
		newDNSCryptStatusCmd(),
	)

	return cmd
}

func newDNSTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test [domain]",
		Short: "Test DNS resolution",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := "example.com"
			if len(args) > 0 {
				domain = args[0]
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}

			// Test via local dnsmasq.
			resolver := intdns.NewResolver("127.0.0.1")
			fmt.Printf("Resolving %s via 127.0.0.1...\n", domain)
			ips, err := resolver.ResolveToStrings(cmd.Context(), domain)
			if err != nil {
				fmt.Printf("  Error: %v\n", err)
			} else {
				for _, ip := range ips {
					fmt.Printf("  %s\n", ip)
				}
			}

			// Test via configured upstream.
			resolver2 := intdns.NewResolver(cfg.DNS.Primary)
			fmt.Printf("\nResolving %s via %s...\n", domain, cfg.DNS.Primary)
			ips2, err := resolver2.ResolveToStrings(cmd.Context(), domain)
			if err != nil {
				fmt.Printf("  Error: %v\n", err)
			} else {
				for _, ip := range ips2 {
					fmt.Printf("  %s\n", ip)
				}
			}

			return nil
		},
	}
}

func newDNSCryptOnCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "crypt-on",
		Short: "Enable dnscrypt-proxy2",
		RunE: func(cmd *cobra.Command, args []string) error {
			d := intdns.NewDNSCrypt()
			if !d.IsInstalled() {
				return fmt.Errorf("dnscrypt-proxy2 is not installed")
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}
			cfg.DNSCrypt.Enabled = true
			if err := config.Save(cfg); err != nil {
				return err
			}

			if err := d.Enable(cmd.Context()); err != nil {
				return err
			}
			fmt.Println("dnscrypt-proxy2 enabled.")
			return nil
		},
	}
}

func newDNSCryptOffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "crypt-off",
		Short: "Disable dnscrypt-proxy2",
		RunE: func(cmd *cobra.Command, args []string) error {
			d := intdns.NewDNSCrypt()

			cfg, err := config.Load()
			if err != nil {
				return err
			}
			cfg.DNSCrypt.Enabled = false
			if err := config.Save(cfg); err != nil {
				return err
			}

			if err := d.Disable(cmd.Context()); err != nil {
				return err
			}
			fmt.Println("dnscrypt-proxy2 disabled.")
			return nil
		},
	}
}

func newDNSCryptStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "crypt-status",
		Short: "Show dnscrypt-proxy2 status",
		RunE: func(cmd *cobra.Command, args []string) error {
			d := intdns.NewDNSCrypt()
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			fmt.Println("dnscrypt-proxy2:")
			fmt.Printf("  Installed: %v\n", d.IsInstalled())
			fmt.Printf("  Running:   %v\n", d.IsRunning(cmd.Context()))
			fmt.Printf("  Enabled:   %v\n", cfg.DNSCrypt.Enabled)
			fmt.Printf("  Port:      %d\n", cfg.DNSCrypt.Port)
			return nil
		},
	}
}
