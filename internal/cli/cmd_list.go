package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/guras256/keenetic-split-tunnel/internal/group"
)

func newListCmd() *cobra.Command {
	var groupName string

	cmd := &cobra.Command{
		Use:   "list [filter]",
		Short: "List entries in a group or all groups",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store := group.NewDefaultStore()

			var filter string
			if len(args) > 0 {
				filter = strings.ToLower(args[0])
			}

			if groupName != "" {
				return listGroup(store, groupName, filter)
			}
			return listAll(store, filter)
		},
	}

	cmd.Flags().StringVarP(&groupName, "group", "g", "", "show only this group")
	return cmd
}

func listGroup(store *group.Store, name, filter string) error {
	g, err := store.Get(name)
	if err != nil {
		return err
	}
	printGroup(g, filter)
	return nil
}

func listAll(store *group.Store, filter string) error {
	groups, err := store.List()
	if err != nil {
		return err
	}
	if len(groups) == 0 {
		fmt.Println("No groups configured.")
		return nil
	}
	for i := range groups {
		if i > 0 {
			fmt.Println()
		}
		printGroup(&groups[i], filter)
	}
	return nil
}

func printGroup(g *group.Group, filter string) {
	status := "enabled"
	if !g.Enabled {
		status = "disabled"
	}
	fmt.Printf("[%s] (%s)", g.Name, status)
	if g.Description != "" {
		fmt.Printf(" — %s", g.Description)
	}
	fmt.Println()

	count := 0
	for _, e := range g.Entries {
		if filter != "" && !strings.Contains(strings.ToLower(e.Value), filter) {
			continue
		}
		fmt.Printf("  %s\n", e.Value)
		count++
	}
	if count == 0 && filter != "" {
		fmt.Println("  (no matching entries)")
	}
	if count == 0 && filter == "" {
		fmt.Println("  (empty)")
	}
}
