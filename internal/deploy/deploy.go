package deploy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/egorlepa/netshunt/internal/platform"
)

// Dependency describes a required system package/binary.
type Dependency struct {
	Name    string // human-readable name
	Binary  string // binary to check in PATH
	Package string // opkg package name
}

// requiredDeps lists packages required by netshunt in all configurations.
var requiredDeps = []Dependency{
	{Name: "ipset", Binary: "ipset", Package: "ipset"},
	{Name: "iptables", Binary: "iptables", Package: "iptables"},
	{Name: "ip", Binary: "ip", Package: "ip-full"},
	{Name: "dnscrypt-proxy", Binary: "dnscrypt-proxy", Package: "dnscrypt-proxy2"},
}

// CheckResult holds the result of a dependency check.
type CheckResult struct {
	Dep       Dependency
	Installed bool
}

// CheckDependencies verifies that required binaries are available.
func CheckDependencies() []CheckResult {
	var missing []CheckResult
	for _, dep := range requiredDeps {
		if !binaryExists(dep.Binary) {
			missing = append(missing, CheckResult{Dep: dep, Installed: false})
		}
	}
	return missing
}

func binaryExists(name string) bool {
	_, err := lookPath(name)
	return err == nil
}

func lookPath(name string) (string, error) {
	// Check common Entware paths explicitly since PATH might not include them.
	for _, dir := range []string{"/opt/bin", "/opt/sbin", "/opt/usr/bin", "/opt/usr/sbin", "/usr/bin", "/usr/sbin", "/bin", "/sbin"} {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found", name)
}

// ndmHook maps a source script path to its destination under /opt/etc/ndm/.
type ndmHook struct {
	subdir string // e.g., "fs.d"
	name   string // e.g., "100-ipset"
}

var ndmHooks = []ndmHook{
	{"fs.d", "100-ipset"},
	{"netfilter.d", "100-proxy-redirect"},
	{"netfilter.d", "100-dns-local"},
	{"ifstatechanged.d", "100-unblock"},
	{"wan.d", "internet-up"},
}

// InstallNDMHooks copies NDM hook scripts to /opt/etc/ndm/.
// It reads scripts from the embedded locations (installed by IPK at /opt/etc/netshunt/ndm/)
// or falls back to generating minimal scripts.
func InstallNDMHooks() (int, error) {
	installed := 0
	for _, h := range ndmHooks {
		destDir := filepath.Join(platform.NDMDir, h.subdir)
		if err := os.MkdirAll(destDir, 0o755); err != nil {
			return installed, fmt.Errorf("create %s: %w", destDir, err)
		}

		dest := filepath.Join(destDir, h.name)

		// Try to copy from the IPK-installed source first.
		src := filepath.Join(platform.ConfigDir, "ndm", h.subdir, h.name)
		if data, err := os.ReadFile(src); err == nil {
			if err := os.WriteFile(dest, data, 0o755); err != nil {
				return installed, fmt.Errorf("write %s: %w", dest, err)
			}
			installed++
			continue
		}

		// Generate a minimal hook script.
		script := fmt.Sprintf("#!/bin/sh\n[ -x %s ] && %s hook %s \"$@\"\n",
			platform.BinaryPath, platform.BinaryPath, hookEvent(h))
		if err := os.WriteFile(dest, []byte(script), 0o755); err != nil {
			return installed, fmt.Errorf("write %s: %w", dest, err)
		}
		installed++
	}
	return installed, nil
}

// InstallInitScript installs the init.d startup script.
func InstallInitScript() error {
	script := fmt.Sprintf(`#!/bin/sh
PIDFILE=%s
BINARY=%s
PATH=/opt/sbin:/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

is_running() {
    [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

case "$1" in
    start)
        if is_running; then
            echo "netshunt daemon already running (pid $(cat $PIDFILE))"
            exit 0
        fi
        start-stop-daemon -S -b -m -p "$PIDFILE" -a "$BINARY" -- daemon
        echo "netshunt daemon started"
        ;;
    stop)
        if is_running; then
            kill "$(cat "$PIDFILE")" 2>/dev/null
            rm -f "$PIDFILE"
            echo "netshunt daemon stopped"
        else
            echo "netshunt daemon not running"
        fi
        ;;
    restart)
        $0 stop
        sleep 1
        $0 start
        ;;
    status)
        if is_running; then
            echo "netshunt daemon running (pid $(cat $PIDFILE))"
        else
            echo "netshunt daemon stopped"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
`, platform.PidFile, platform.BinaryPath)
	return os.WriteFile(platform.InitScript, []byte(script), 0o755)
}

// EnsureDirectories creates all required directories.
func EnsureDirectories() error {
	dirs := []string{
		platform.ConfigDir,
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
	}
	return nil
}

// EnsureTproxyModule tries to load the xt_TPROXY kernel module.
// On Keenetic routers modprobe is not available, so we fall back to insmod.
func EnsureTproxyModule(ctx context.Context) {
	if platform.RunSilent(ctx, "modprobe", "xt_TPROXY") == nil {
		return
	}
	rel, err := platform.Run(ctx, "uname", "-r")
	if err != nil {
		return
	}
	_ = platform.RunSilent(ctx, "insmod", "/lib/modules/"+strings.TrimSpace(rel)+"/xt_TPROXY.ko")
}

// CheckIPTablesTproxy tests whether iptables supports the TPROXY target
// by loading the kernel module and attempting to add a TPROXY rule.
func CheckIPTablesTproxy(ctx context.Context) bool {
	EnsureTproxyModule(ctx)

	const testChain = "__netshunt_tproxy_test"
	if err := platform.RunSilent(ctx, "iptables", "-t", "mangle", "-N", testChain); err != nil {
		return false
	}
	ok := platform.RunSilent(ctx, "iptables", "-t", "mangle", "-A", testChain,
		"-p", "udp", "-j", "TPROXY", "--on-port", "0", "--tproxy-mark", "0x0/0x0") == nil
	_ = platform.RunSilent(ctx, "iptables", "-t", "mangle", "-F", testChain)
	_ = platform.RunSilent(ctx, "iptables", "-t", "mangle", "-X", testChain)
	return ok
}

// InstallOpkgDeps attempts to install missing packages via opkg.
func InstallOpkgDeps(ctx context.Context, packages []string) error {
	args := append([]string{"install"}, packages...)
	return platform.RunSilent(ctx, "opkg", args...)
}

// UpgradeOpkgDeps attempts to upgrade packages via opkg.
func UpgradeOpkgDeps(ctx context.Context, packages []string) error {
	args := append([]string{"upgrade"}, packages...)
	return platform.RunSilent(ctx, "opkg", args...)
}

// UninstallNDMHooks removes all NDM hook scripts installed by netshunt.
func UninstallNDMHooks() {
	for _, h := range ndmHooks {
		dest := filepath.Join(platform.NDMDir, h.subdir, h.name)
		os.Remove(dest)
	}
}

func hookEvent(h ndmHook) string {
	switch h.subdir {
	case "fs.d":
		return "fs"
	case "netfilter.d":
		return "netfilter"
	case "ifstatechanged.d":
		return "ifstate"
	case "wan.d":
		return "wan"
	default:
		return h.subdir
	}
}
