package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/egorlepa/netshunt/internal/cli"
)

var version = "dev"

func main() {
	loadTimezone()
	cli.SetVersion(version)
	if err := cli.NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// loadTimezone sets time.Local from /etc/TZ on Keenetic routers.
// Go expects a TZ env var or binary zoneinfo at /etc/localtime, neither of
// which exist on Keenetic. This parses the POSIX TZ string (e.g. "MSK-3")
// and sets time.Local to the corresponding fixed zone.
func loadTimezone() {
	if os.Getenv("TZ") != "" {
		return
	}
	b, err := os.ReadFile("/etc/TZ")
	if err != nil {
		return
	}
	tz := strings.TrimSpace(string(b))
	// Parse "NAME[+-]OFFSET" (e.g. "MSK-3", "EST5", "CST-8").
	// POSIX sign convention is inverted: negative = east of UTC.
	i := strings.IndexAny(tz, "+-0123456789")
	if i <= 0 {
		return
	}
	hours, err := strconv.Atoi(tz[i:])
	if err != nil {
		return
	}
	time.Local = time.FixedZone(tz[:i], -hours*3600)
}
