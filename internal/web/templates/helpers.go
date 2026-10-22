package templates

import (
	"encoding/hex"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/shunt"
)

func autoUpdateSchedule(au config.AutoUpdateConfig, fallback string) string {
	if au.Schedule != "" {
		return au.Schedule
	}
	return fallback
}

// SlugID converts a string to a unique, CSS-safe HTML ID fragment via hex encoding.
func SlugID(s string) string {
	return hex.EncodeToString([]byte(s))
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

func itoaOrEmpty(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func joinLines(ss []string) string {
	return strings.Join(ss, "\n")
}

// sortedEntries returns entries sorted by type: domains, IPs, CIDRs.
func sortedEntries(entries []shunt.Entry) []shunt.Entry {
	sorted := make([]shunt.Entry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		ti, tj := sorted[i].Type(), sorted[j].Type()
		if ti != tj {
			return ti < tj
		}
		return sorted[i].Value < sorted[j].Value
	})
	return sorted
}

func logLevelClass(level string) string {
	switch level {
	case "ERROR":
		return "log-level text-red"
	case "WARN":
		return "log-level text-yellow"
	default:
		return "log-level text-muted"
	}
}

// shuntPath returns the URL path for a shunt, with the name escaped so names
// with spaces, slashes or '#' survive the round trip.
func shuntPath(name string) string {
	return "/shunts/" + url.PathEscape(name)
}

// entryPath returns the URL path for one entry of a shunt. Values such as
// regexp:^a#b?c or 1.2.3.0/24 must be escaped: the mux decodes each segment
// back in PathValue, '%2F' included.
func entryPath(shunt, value string) string {
	return shuntPath(shunt) + "/entries/" + url.PathEscape(value)
}
