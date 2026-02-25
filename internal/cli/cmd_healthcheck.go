package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/spf13/cobra"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/healthcheck"
	"github.com/egorlepa/netshunt/internal/shunt"
)

func newTestCmd() *cobra.Command {
	var domain string

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run end-to-end health checks on the split tunnel pipeline",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			store := shunt.NewDefaultStore()

			results := healthcheck.RunChecks(ctx, cfg, store)
			allPassed := PrintResults(results)

			// Probe domain: --domain overrides the default (ifconfig.me).
			probeDomain := "ifconfig.me"
			if domain != "" {
				probeDomain = domain
			}

			// Ensure the probe domain is in a shunt via the daemon API.
			_ = store.EnsureDefaultShunt()
			ensureDomainInShunt(cfg, probeDomain)

			fmt.Println()
			if !printDomainProbe(ctx, cfg, probeDomain) {
				allPassed = false
			}

			if !allPassed {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&domain, "domain", "d", "", "domain to probe (default: ifconfig.me)")
	return cmd
}

// ensureDomainInShunt adds a domain to the default shunt via the daemon HTTP
// API and triggers a reconcile. Silently ignores errors (daemon may not be running).
func ensureDomainInShunt(cfg *config.Config, domain string) {
	base := fmt.Sprintf("http://127.0.0.1%s", cfg.Daemon.WebListen)

	// Add entry.
	resp, err := http.PostForm(base+"/api/entries", url.Values{
		"shunt": {shunt.DefaultShuntName},
		"value": {domain},
	})
	if err != nil {
		printWarn(fmt.Sprintf("could not add %s to default shunt (daemon not running?)", domain))
		return
	}
	resp.Body.Close()

	// Trigger reconcile.
	resp, err = http.Post(base+"/api/reconcile", "", nil)
	if err == nil {
		resp.Body.Close()
	}
}

// PrintResults prints health check results with colored output and returns true if all passed.
func PrintResults(results []healthcheck.Result) bool {
	allPassed := true
	for _, r := range results {
		if r.Passed {
			printPass(r.Name + ": " + r.Detail)
		} else {
			printFail(r.Name + ": " + r.Detail)
			allPassed = false
		}
	}
	return allPassed
}

func printPass(msg string) {
	fmt.Printf("  \033[32m✓\033[0m %s\n", msg)
}

func printFail(msg string) {
	fmt.Printf("  \033[31m✗\033[0m %s\n", msg)
}

func printWarn(msg string) {
	fmt.Printf("  \033[33m!\033[0m %s\n", msg)
}

// printDomainProbe runs a domain probe and prints the results. Returns true if all IPs are in the ipset.
func printDomainProbe(ctx context.Context, cfg *config.Config, domain string) bool {
	fmt.Printf("  Domain probe: %s\n", domain)
	probe, err := healthcheck.ProbeDomain(ctx, cfg, domain)
	if err != nil {
		fmt.Printf("    \033[31m✗\033[0m %v\n", err)
		return false
	}
	if len(probe.IPs) == 0 {
		fmt.Printf("    \033[31m✗\033[0m no IPs resolved\n")
		return false
	}
	passed := true
	for _, ip := range probe.IPs {
		if probe.InIPSet[ip] {
			fmt.Printf("    \033[32m✓\033[0m %s in ipset\n", ip)
		} else {
			fmt.Printf("    \033[31m✗\033[0m %s not in ipset\n", ip)
			passed = false
		}
	}
	return passed
}
