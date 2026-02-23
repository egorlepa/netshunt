package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/egorlepa/netshunt/internal/shunt"
)

func newShuntCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shunt",
		Short: "Manage shunts",
	}

	cmd.AddCommand(
		newShuntListCmd(),
		newShuntCreateCmd(),
		newShuntDeleteCmd(),
		newShuntEnableCmd(),
		newShuntDisableCmd(),
		newShuntImportCmd(),
		newShuntExportCmd(),
	)

	return cmd
}

func newShuntListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all shunts",
		RunE: func(cmd *cobra.Command, args []string) error {
			store := shunt.NewDefaultStore()
			shunts, err := store.List()
			if err != nil {
				return err
			}
			if len(shunts) == 0 {
				fmt.Println("No shunts configured.")
				return nil
			}
			for _, sh := range shunts {
				status := "enabled"
				if !sh.Enabled {
					status = "disabled"
				}
				desc := ""
				if sh.Description != "" {
					desc = " — " + sh.Description
				}
				fmt.Printf("  %-20s [%s] %d entries%s\n", sh.Name, status, len(sh.Entries), desc)
			}
			return nil
		},
	}
}

func newShuntCreateCmd() *cobra.Command {
	var description string

	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new empty shunt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store := shunt.NewDefaultStore()
			sh := shunt.Shunt{
				Name:        args[0],
				Description: description,
				Enabled:     true,
			}
			if err := store.Create(sh); err != nil {
				return err
			}
			fmt.Printf("Created shunt %q\n", args[0])
			return nil
		},
	}

	cmd.Flags().StringVarP(&description, "description", "d", "", "shunt description")
	return cmd
}

func newShuntDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a shunt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store := shunt.NewDefaultStore()
			if err := store.Delete(args[0]); err != nil {
				return err
			}
			fmt.Printf("Deleted shunt %q\n", args[0])
			return nil
		},
	}
}

func newShuntEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable <name>",
		Short: "Enable a shunt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store := shunt.NewDefaultStore()
			if err := store.SetEnabled(args[0], true); err != nil {
				return err
			}
			fmt.Printf("Enabled shunt %q\n", args[0])
			return nil
		},
	}
}

func newShuntDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable <name>",
		Short: "Disable a shunt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store := shunt.NewDefaultStore()
			if err := store.SetEnabled(args[0], false); err != nil {
				return err
			}
			fmt.Printf("Disabled shunt %q\n", args[0])
			return nil
		},
	}
}

func newShuntImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <file>",
		Short: "Import shunts from a YAML file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read file: %w", err)
			}

			// If daemon is running, delegate to it so it applies changes.
			if err := daemonImportShunts(cmd.Context(), data); err == nil {
				fmt.Printf("Imported shunts from %s\n", args[0])
				return nil
			}

			// Daemon not running: write directly.
			store := shunt.NewDefaultStore()
			if err := store.ImportShunts(data); err != nil {
				return err
			}
			fmt.Printf("Imported shunts from %s\n", args[0])
			fmt.Println("Note: daemon is not running — start it to reconcile changes.")
			return nil
		},
	}
}

func newShuntExportCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "export [name]",
		Short: "Export shunts to YAML",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store := shunt.NewDefaultStore()

			var data []byte
			var err error
			if len(args) > 0 {
				data, err = store.ExportShunt(args[0])
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
