package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/egorlepa/netshunt/internal/deploy"
	"github.com/egorlepa/netshunt/internal/platform"
)

func newInstallHooksCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install-hooks",
		Short: "Install NDM hooks and init.d script",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Installing NDM hooks...")
			n, err := deploy.InstallNDMHooks()
			if err != nil {
				return fmt.Errorf("install NDM hooks: %w", err)
			}
			fmt.Printf("  Installed %d hooks.\n", n)

			fmt.Println("Installing init.d script...")
			if err := deploy.InstallInitScript(); err != nil {
				return fmt.Errorf("install init script: %w", err)
			}
			fmt.Printf("  Installed %s\n", platform.InitScript)

			fmt.Println("Done.")
			return nil
		},
	}
}
