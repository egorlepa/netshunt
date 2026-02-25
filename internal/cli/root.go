package cli

import (
	"github.com/spf13/cobra"
)

// version is set at build time via ldflags.
var version = "dev"

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "netshunt",
		Short: "netshunt — selective traffic routing through proxy/VPN",
	}
	root.CompletionOptions.DisableDefaultCmd = true

	root.AddCommand(
		newVersionCmd(),
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
