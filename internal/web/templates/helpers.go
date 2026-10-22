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

// ShuntView is a shunt as the Shunts page shows it. Count is the number of
// entries it applies (for a geosite shunt, from the database). NoData is set
// for a geosite shunt the database has nothing for: "database not
// downloaded" or "category not in database".
type ShuntView struct {
	shunt.Shunt
	Count  int
	NoData string
	// Pos is the 0-based position in shunts.yaml, Total the number of
	// shunts; the expanded row shows "Position Pos+1 of Total".
	Pos, Total int
	// Open renders the row expanded: set when the row is re-rendered in
	// answer to an edit made from its own (open) panel.
	Open bool
}

// ShuntsPageData is what the Shunts page renders.
type ShuntsPageData struct {
	Shunts []ShuntView
	// IPSetMembers is the tracker's ipset member count, -1 when unknown.
	IPSetMembers int
}

// Enabled is the number of enabled shunts.
func (d ShuntsPageData) Enabled() int {
	n := 0
	for _, v := range d.Shunts {
		if v.Enabled {
			n++
		}
	}
	return n
}

// Entries is the number of entries over all shunts (geosite ones counted
// from the database), as the summary strip shows it.
func (d ShuntsPageData) Entries() int {
	n := 0
	for _, v := range d.Shunts {
		n += v.Count
	}
	return n
}

// groupDigits formats n with a space between thousands ("3 786"), the way
// the page script formats counts it recomputes.
func groupDigits(n int) string {
	s := strconv.Itoa(n)
	if n < 0 {
		return "-" + groupDigits(-n)
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(c)
	}
	return b.String()
}

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
