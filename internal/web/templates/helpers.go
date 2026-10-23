package templates

import (
	"encoding/hex"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"

	"github.com/egorlepa/netshunt/internal/healthcheck"
	"github.com/egorlepa/netshunt/internal/platform"
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

// Num renders a count with the thousands gap element between groups
// ("3<i class="k"></i>786"), the way the page scripts format counts.
func Num(n int) templ.Component {
	return templ.Raw(strings.ReplaceAll(groupDigits(n), " ", `<i class="k"></i>`))
}

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

// splitHealth returns the failed checks (not passed, not a warning) and the
// warnings of a healthcheck run, in check order.
func splitHealth(res []healthcheck.Result) (failing, warning []healthcheck.Result) {
	for _, r := range res {
		switch {
		case r.Passed:
		case r.Warn:
			warning = append(warning, r)
		default:
			failing = append(failing, r)
		}
	}
	return failing, warning
}

// plural renders "1 check failing" / "3 checks failing".
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// sentence ends s with a period unless it already ends with punctuation.
func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasSuffix(s, ".") || strings.HasSuffix(s, "!") || strings.HasSuffix(s, "?") {
		return s
	}
	return s + "."
}

// seconds renders a check duration as "0.31 s".
func seconds(d time.Duration) string {
	return strconv.FormatFloat(d.Seconds(), 'f', 2, 64) + " s"
}

// logAttrs returns the structured attributes of a log entry; entries
// without them (none today) are split from the formatted text.
func logAttrs(e platform.LogEntry) []platform.LogAttr {
	if len(e.KV) > 0 || e.Attrs == "" {
		return e.KV
	}
	var out []platform.LogAttr
	for _, line := range strings.Split(e.Attrs, "\n") {
		k, v, _ := strings.Cut(line, "=")
		out = append(out, platform.LogAttr{Key: k, Value: v})
	}
	return out
}

// attrsText is the attributes of a log entry on one line, for search and
// the tooltip.
func attrsText(e platform.LogEntry) string {
	kv := logAttrs(e)
	parts := make([]string, len(kv))
	for i, a := range kv {
		parts[i] = a.Key + "=" + a.Value
	}
	return strings.Join(parts, " ")
}
