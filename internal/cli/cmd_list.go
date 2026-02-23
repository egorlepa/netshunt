package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/egorlepa/netshunt/internal/shunt"
)

func newListCmd() *cobra.Command {
	var shuntName string

	cmd := &cobra.Command{
		Use:   "list [filter]",
		Short: "List entries in a shunt or all shunts",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store := shunt.NewDefaultStore()

			var filter string
			if len(args) > 0 {
				filter = strings.ToLower(args[0])
			}

			if shuntName != "" {
				return listShunt(store, shuntName, filter)
			}
			return listAll(store, filter)
		},
	}

	cmd.Flags().StringVarP(&shuntName, "shunt", "s", "", "show only this shunt")
	return cmd
}

func listShunt(store *shunt.Store, name, filter string) error {
	sh, err := store.Get(name)
	if err != nil {
		return err
	}
	printShunt(sh, filter)
	return nil
}

func listAll(store *shunt.Store, filter string) error {
	shunts, err := store.List()
	if err != nil {
		return err
	}
	if len(shunts) == 0 {
		fmt.Println("No shunts configured.")
		return nil
	}
	for i := range shunts {
		if i > 0 {
			fmt.Println()
		}
		printShunt(&shunts[i], filter)
	}
	return nil
}

func printShunt(sh *shunt.Shunt, filter string) {
	status := "enabled"
	if !sh.Enabled {
		status = "disabled"
	}
	fmt.Printf("[%s] (%s)", sh.Name, status)
	if sh.Description != "" {
		fmt.Printf(" — %s", sh.Description)
	}
	fmt.Println()

	count := 0
	for _, e := range sh.Entries {
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
