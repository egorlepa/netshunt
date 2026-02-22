package templates

import (
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/egorlepa/netshunt/internal/group"
)

// SlugID converts a string to a unique, CSS-safe HTML ID fragment via hex encoding.
func SlugID(s string) string {
	return hex.EncodeToString([]byte(s))
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

func joinLines(ss []string) string {
	return strings.Join(ss, "\n")
}

// sortedEntries returns entries sorted by type: domains, IPs, CIDRs.
func sortedEntries(entries []group.Entry) []group.Entry {
	sorted := make([]group.Entry, len(entries))
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

func faviconDataURI() string {
	return ""
}
