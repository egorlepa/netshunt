package templates

import (
	"sort"
	"strconv"
	"strings"

	"github.com/guras256/keenetic-split-tunnel/internal/group"
)

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
	return "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='16' fill='%23e94560'/><text x='50' y='68' font-size='48' font-weight='bold' font-family='sans-serif' fill='white' text-anchor='middle'>KST</text></svg>"
}
