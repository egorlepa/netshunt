package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/guras256/keenetic-split-tunnel/internal/group"
)

func newDelCmd() *cobra.Command {
	var groupName string

	cmd := &cobra.Command{
		Use:   "del <host>",
		Short: "Remove a domain, IP, or CIDR from a group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if groupName == "" {
				groupName = group.DefaultGroupName
			}

			// If daemon is running, delegate to it — it writes and applies atomically.
			if err := daemonRemoveEntry(ctx, groupName, args[0]); err == nil {
				fmt.Printf("Removed %q from group %q\n", args[0], groupName)
				return nil
			}

			// Daemon not running: write directly.
			store := group.NewDefaultStore()
			if err := store.RemoveEntry(groupName, args[0]); err != nil {
				return err
			}
			fmt.Printf("Removed %q from group %q\n", args[0], groupName)
			fmt.Println("Note: daemon is not running — start it to apply changes.")
			return nil
		},
	}

	cmd.Flags().StringVarP(&groupName, "group", "g", "", "target group (default: Default)")
	return cmd
}
