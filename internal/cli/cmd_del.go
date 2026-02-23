package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/egorlepa/netshunt/internal/shunt"
)

func newDelCmd() *cobra.Command {
	var shuntName string

	cmd := &cobra.Command{
		Use:   "del <host>",
		Short: "Remove a domain, IP, or CIDR from a shunt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if shuntName == "" {
				shuntName = shunt.DefaultShuntName
			}

			// If daemon is running, delegate to it — it writes and applies atomically.
			if err := daemonRemoveEntry(ctx, shuntName, args[0]); err == nil {
				fmt.Printf("Removed %q from shunt %q\n", args[0], shuntName)
				return nil
			}

			// Daemon not running: write directly.
			store := shunt.NewDefaultStore()
			if err := store.RemoveEntry(shuntName, args[0]); err != nil {
				return err
			}
			fmt.Printf("Removed %q from shunt %q\n", args[0], shuntName)
			fmt.Println("Note: daemon is not running — start it to reconcile changes.")
			return nil
		},
	}

	cmd.Flags().StringVarP(&shuntName, "shunt", "s", "", "target shunt (default: Default)")
	return cmd
}
