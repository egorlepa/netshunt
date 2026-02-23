package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/egorlepa/netshunt/internal/shunt"
)

func newAddCmd() *cobra.Command {
	var shuntName string

	cmd := &cobra.Command{
		Use:   "add <host>",
		Short: "Add a domain, IP, or CIDR to a shunt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if shuntName == "" {
				shuntName = shunt.DefaultShuntName
			}

			// If daemon is running, delegate to it — it writes and applies atomically.
			if err := daemonAddEntry(ctx, shuntName, args[0]); err == nil {
				fmt.Printf("Added %q to shunt %q\n", args[0], shuntName)
				return nil
			}

			// Daemon not running: write directly.
			store := shunt.NewDefaultStore()
			if err := store.EnsureDefaultShunt(); err != nil {
				return err
			}
			if err := store.AddEntry(shuntName, args[0]); err != nil {
				return err
			}
			fmt.Printf("Added %q to shunt %q\n", args[0], shuntName)
			fmt.Println("Note: daemon is not running — start it to reconcile changes.")
			return nil
		},
	}

	cmd.Flags().StringVarP(&shuntName, "shunt", "s", "", "target shunt (default: Default)")
	return cmd
}
