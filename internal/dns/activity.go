package dns

import (
	"cmp"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// activityCap is the number of matched answers the activity ring keeps.
const activityCap = 500

// activityMinutes is the window of the per-shunt and per-client counters.
const activityMinutes = 60

// ActivityEntry is one shunt-matched DNS answer as the dashboard feed shows
// it. Name is the name a rule matched (the query name or a name of its
// CNAME chain); QName is the query name when it differs. Dim is the number
// of leading bytes of Name the rule does not cover (the "www." before a
// suffix rule), 0 for exact, keyword and regexp rules.
type ActivityEntry struct {
	Seq    uint64    `json:"seq"`
	Time   time.Time `json:"t"`
	Client string    `json:"c"`
	Name   string    `json:"d"`
	QName  string    `json:"q,omitempty"`
	Shunt  string    `json:"s"`
	Dim    int       `json:"dim"`
}

// ActivityCount is a name (shunt or client) with its number of matched
// answers.
type ActivityCount struct {
	Name string `json:"name"`
	N    int    `json:"n"`
}

type activityBucket struct {
	minute  int64 // Unix minute the counters belong to
	shunts  map[string]int
	clients map[string]int
}

// Activity records shunt-matched DNS answers: a ring of the last
// activityCap entries with increasing sequence numbers, and per-minute
// counters by shunt and by client for the last hour. Safe for concurrent
// use; Record is on the DNS path and only takes a mutex.
type Activity struct {
	mu      sync.Mutex
	ring    []ActivityEntry // len <= activityCap, ring[next] is the oldest once full
	next    int
	seq     uint64
	buckets [activityMinutes]activityBucket
	now     func() time.Time
}

// NewActivity returns an empty activity log.
func NewActivity() *Activity {
	return &Activity{ring: make([]ActivityEntry, 0, activityCap), now: time.Now}
}

// Record adds a matched answer. client is the requester's IP ("" when
// unknown, then it is not counted per client); name is the matched name and
// info the rule that matched it.
func (a *Activity) Record(client, qname, name string, info MatchInfo) {
	dim := 0
	if info.Kind == MatchSuffix && len(info.Rule) < len(name) {
		dim = len(name) - len(info.Rule)
	}
	if qname == name {
		qname = ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.seq++
	e := ActivityEntry{Seq: a.seq, Time: now, Client: client, Name: name, QName: qname, Shunt: info.Shunt, Dim: dim}
	if len(a.ring) < activityCap {
		a.ring = append(a.ring, e)
	} else {
		a.ring[a.next] = e
		a.next = (a.next + 1) % activityCap
	}

	minute := now.Unix() / 60
	b := &a.buckets[minute%activityMinutes]
	if b.minute != minute || b.shunts == nil {
		*b = activityBucket{minute: minute, shunts: map[string]int{}, clients: map[string]int{}}
	}
	b.shunts[info.Shunt]++
	if client != "" {
		b.clients[client]++
	}
}

// Since returns up to limit entries newer than seq, newest first, the
// latest sequence number and the number of entries the ring holds.
func (a *Activity) Since(seq uint64, limit int) (entries []ActivityEntry, last uint64, held int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := len(a.ring)
	for i := 0; i < n && len(entries) < limit; i++ {
		// Newest is just before next; before the ring is full next is 0
		// and this is the end of the slice.
		idx := (a.next - 1 - i + n) % n
		e := a.ring[idx]
		if e.Seq <= seq {
			break
		}
		entries = append(entries, e)
	}
	return entries, a.seq, n
}

// LastHour sums the per-minute counters of the last activityMinutes
// minutes (the current one included), sorted by count, then name.
func (a *Activity) LastHour() (shunts, clients []ActivityCount) {
	a.mu.Lock()
	minute := a.now().Unix() / 60
	sh, cl := map[string]int{}, map[string]int{}
	for i := range a.buckets {
		b := &a.buckets[i]
		if b.shunts == nil || b.minute <= minute-activityMinutes || b.minute > minute {
			continue
		}
		for k, v := range b.shunts {
			sh[k] += v
		}
		for k, v := range b.clients {
			cl[k] += v
		}
	}
	a.mu.Unlock()
	return sortedCounts(sh), sortedCounts(cl)
}

func sortedCounts(m map[string]int) []ActivityCount {
	out := make([]ActivityCount, 0, len(m))
	for k, v := range m {
		out = append(out, ActivityCount{Name: k, N: v})
	}
	slices.SortFunc(out, func(x, y ActivityCount) int {
		if c := cmp.Compare(y.N, x.N); c != 0 {
			return c
		}
		return cmp.Compare(x.Name, y.Name)
	})
	return out
}

// clientIP returns the IP of a DNS client address, "" when it has none.
func clientIP(addr net.Addr) string {
	var ip net.IP
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.TCPAddr:
		ip = a.IP
	default:
		if addr == nil {
			return ""
		}
		if ap, err := netip.ParseAddrPort(addr.String()); err == nil {
			return ap.Addr().Unmap().String()
		}
		return ""
	}
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}
