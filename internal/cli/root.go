package cli

import (
	"github.com/spf13/cobra"
)

// version is set at build time via ldflags.
var version = "dev"

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "kst",
		Short: "Keenetic Split Tunnel — selective traffic routing through proxy/VPN",
	}
	root.CompletionOptions.DisableDefaultCmd = true

	root.AddCommand(
		newVersionCmd(),
		newAddCmd(),
		newDelCmd(),
		newListCmd(),
		newGroupCmd(),
		newReconcileCmd(),
		newDaemonCmd(),
		newTestCmd(),
		newDebugCmd(),
		newSetupCmd(),
		newDNSCmd(),
		newHookCmd(),
		newInstallHooksCmd(),
		newUninstallCmd(),
	)

	return root
}

// SetVersion sets the version string (called from main).
func SetVersion(v string) {
	version = v
}
