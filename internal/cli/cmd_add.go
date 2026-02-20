package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/guras256/keenetic-split-tunnel/internal/group"
)

func newAddCmd() *cobra.Command {
	var groupName string

	cmd := &cobra.Command{
		Use:   "add <host>",
		Short: "Add a domain, IP, or CIDR to a group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store := group.NewDefaultStore()
			if err := store.EnsureDefaultGroup(); err != nil {
				return err
			}

			if groupName == "" {
				groupName = group.DefaultGroupName
			}

			if err := store.AddEntry(groupName, args[0]); err != nil {
				return err
			}
			fmt.Printf("Added %q to group %q\n", args[0], groupName)
			return nil
		},
	}

	cmd.Flags().StringVarP(&groupName, "group", "g", "", "target group (default: Default)")
	return cmd
}
