package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/healthcheck"
	"github.com/egorlepa/netshunt/internal/shunt"
)

func newTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Run end-to-end health checks on the split tunnel pipeline",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			results := healthcheck.RunChecks(cmd.Context(), cfg, shunt.NewDefaultStore())
			if !PrintResults(results) {
				os.Exit(1)
			}
			return nil
		},
	}
}

// PrintResults prints health check results with colored output and returns true if all passed.
func PrintResults(results []healthcheck.Result) bool {
	allPassed := true
	for _, r := range results {
		switch {
		case r.Passed:
			printPass(r.Name + ": " + r.Detail)
		case r.Warn:
			printWarn(r.Name + ": " + r.Detail)
		default:
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
