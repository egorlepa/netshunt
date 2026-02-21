package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/guras256/keenetic-split-tunnel/internal/group"
)

func newGroupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "group",
		Short: "Manage host groups",
	}

	cmd.AddCommand(
		newGroupListCmd(),
		newGroupCreateCmd(),
		newGroupDeleteCmd(),
		newGroupEnableCmd(),
		newGroupDisableCmd(),
		newGroupImportCmd(),
		newGroupExportCmd(),
	)

	return cmd
}

func newGroupListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all groups",
		RunE: func(cmd *cobra.Command, args []string) error {
			store := group.NewDefaultStore()
			groups, err := store.List()
			if err != nil {
				return err
			}
			if len(groups) == 0 {
				fmt.Println("No groups configured.")
				return nil
			}
			for _, g := range groups {
				status := "enabled"
				if !g.Enabled {
					status = "disabled"
				}
				desc := ""
				if g.Description != "" {
					desc = " — " + g.Description
				}
				fmt.Printf("  %-20s [%s] %d entries%s\n", g.Name, status, len(g.Entries), desc)
			}
			return nil
		},
	}
}

func newGroupCreateCmd() *cobra.Command {
	var description string

	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new empty group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store := group.NewDefaultStore()
			g := group.Group{
				Name:        args[0],
				Description: description,
				Enabled:     true,
			}
			if err := store.Create(g); err != nil {
				return err
			}
			fmt.Printf("Created group %q\n", args[0])
			return nil
		},
	}

	cmd.Flags().StringVarP(&description, "description", "d", "", "group description")
	return cmd
}

func newGroupDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store := group.NewDefaultStore()
			if err := store.Delete(args[0]); err != nil {
				return err
			}
			fmt.Printf("Deleted group %q\n", args[0])
			return nil
		},
	}
}

func newGroupEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable <name>",
		Short: "Enable a group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store := group.NewDefaultStore()
			if err := store.SetEnabled(args[0], true); err != nil {
				return err
			}
			fmt.Printf("Enabled group %q\n", args[0])
			return nil
		},
	}
}

func newGroupDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable <name>",
		Short: "Disable a group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store := group.NewDefaultStore()
			if err := store.SetEnabled(args[0], false); err != nil {
				return err
			}
			fmt.Printf("Disabled group %q\n", args[0])
			return nil
		},
	}
}

func newGroupImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <file>",
		Short: "Import groups from a YAML file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read file: %w", err)
			}

			// If daemon is running, delegate to it so it applies changes.
			if err := daemonImportGroups(cmd.Context(), data); err == nil {
				fmt.Printf("Imported groups from %s\n", args[0])
				return nil
			}

			// Daemon not running: write directly.
			store := group.NewDefaultStore()
			if err := store.ImportGroups(data); err != nil {
				return err
			}
			fmt.Printf("Imported groups from %s\n", args[0])
			fmt.Println("Note: daemon is not running — start it to apply changes.")
			return nil
		},
	}
}

func newGroupExportCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "export [name]",
		Short: "Export groups to YAML",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store := group.NewDefaultStore()

			var data []byte
			var err error
			if len(args) > 0 {
				data, err = store.ExportGroup(args[0])
			} else {
				data, err = store.ExportAll()
			}
			if err != nil {
				return err
			}

			if output != "" {
				if err := os.WriteFile(output, data, 0644); err != nil {
					return fmt.Errorf("write file: %w", err)
				}
				fmt.Printf("Exported to %s\n", output)
				return nil
			}

			fmt.Print(string(data))
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default: stdout)")
	return cmd
}
