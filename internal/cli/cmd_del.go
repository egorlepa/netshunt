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
			store := group.NewDefaultStore()

			if groupName == "" {
				groupName = group.DefaultGroupName
			}

			if err := store.RemoveEntry(groupName, args[0]); err != nil {
				return err
			}
			fmt.Printf("Removed %q from group %q\n", args[0], groupName)
			return nil
		},
	}

	cmd.Flags().StringVarP(&groupName, "group", "g", "", "target group (default: Default)")
	return cmd
}
