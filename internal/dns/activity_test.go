package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"

	"github.com/egorlepa/netshunt/internal/shunt"
)

func TestActivityRingSinceNewestFirst(t *testing.T) {
	a := NewActivity()
	if got, last, held := a.Since(0, 60); len(got) != 0 || last != 0 || held != 0 {
		t.Fatalf("empty: %v %d %d", got, last, held)
	}
	for i := range 3 {
		a.Record("10.0.0.1", fmt.Sprintf("q%d.example.com", i), fmt.Sprintf("q%d.example.com", i), MatchInfo{Shunt: "S", Kind: MatchSuffix, Rule: "example.com"})
	}
	got, last, held := a.Since(0, 60)
	if last != 3 || held != 3 || len(got) != 3 || got[0].Seq != 3 || got[2].Seq != 1 {
		t.Fatalf("since 0: %+v last=%d held=%d", got, last, held)
	}
	if got[0].Dim != len("q2.") || got[0].QName != "" {
		t.Errorf("dim/qname: %+v", got[0])
	}
	got, _, _ = a.Since(2, 60)
	if len(got) != 1 || got[0].Seq != 3 {
		t.Errorf("since 2: %+v", got)
	}
	if got, _, _ := a.Since(3, 60); len(got) != 0 {
		t.Errorf("since last: %+v", got)
	}
}

func TestActivityRingWrapsAndLimits(t *testing.T) {
	a := NewActivity()
	for i := range activityCap + 20 {
		a.Record("", "x.com", "x.com", MatchInfo{Shunt: fmt.Sprint(i), Kind: MatchExact, Rule: "x.com"})
	}
	got, last, held := a.Since(0, 1000)
	if held != activityCap || len(got) != activityCap || last != activityCap+20 {
		t.Fatalf("held=%d got=%d last=%d", held, len(got), last)
	}
	if got[0].Seq != activityCap+20 || got[len(got)-1].Seq != 21 {
		t.Errorf("order: first %d last %d", got[0].Seq, got[len(got)-1].Seq)
	}
	for i := 1; i < len(got); i++ {
		if got[i].Seq != got[i-1].Seq-1 {
			t.Fatalf("not contiguous at %d: %d after %d", i, got[i].Seq, got[i-1].Seq)
		}
	}
	if got, _, _ := a.Since(0, 60); len(got) != 60 || got[0].Seq != activityCap+20 {
		t.Errorf("limit: %d entries, first %d", len(got), got[0].Seq)
	}
	if got[0].Dim != 0 {
		t.Errorf("exact rule dims: %+v", got[0])
	}
}

func TestActivityLastHourBuckets(t *testing.T) {
	a := NewActivity()
	now := time.Date(2026, 10, 23, 12, 0, 30, 0, time.UTC)
	a.now = func() time.Time { return now }
	rec := func(client, sh string) {
		a.Record(client, "a.com", "a.com", MatchInfo{Shunt: sh, Kind: MatchSuffix, Rule: "a.com"})
	}
	rec("10.0.0.1", "YOUTUBE")
	rec("10.0.0.1", "YOUTUBE")
	rec("10.0.0.2", "GOOGLE")
	rec("", "GOOGLE") // unknown client: counted per shunt only

	now = now.Add(59 * time.Minute) // first minute still inside the hour
	rec("10.0.0.2", "GOOGLE")
	shunts, clients := a.LastHour()
	wantS := []ActivityCount{{"GOOGLE", 3}, {"YOUTUBE", 2}}
	wantC := []ActivityCount{{"10.0.0.1", 2}, {"10.0.0.2", 2}}
	if !reflect.DeepEqual(shunts, wantS) || !reflect.DeepEqual(clients, wantC) {
		t.Fatalf("hour: %v %v", shunts, clients)
	}

	now = now.Add(time.Minute) // the 12:00 minute falls out
	shunts, clients = a.LastHour()
	if !reflect.DeepEqual(shunts, []ActivityCount{{"GOOGLE", 1}}) || !reflect.DeepEqual(clients, []ActivityCount{{"10.0.0.2", 1}}) {
		t.Fatalf("after an hour: %v %v", shunts, clients)
	}

	// A bucket slot reused 60 minutes later starts from zero.
	rec("10.0.0.3", "NEW")
	shunts, _ = a.LastHour()
	if !reflect.DeepEqual(shunts, []ActivityCount{{"GOOGLE", 1}, {"NEW", 1}}) {
		t.Fatalf("reused slot: %v", shunts)
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		addr net.Addr
		want string
	}{
		{&net.UDPAddr{IP: net.IPv4(192, 168, 1, 21), Port: 5353}, "192.168.1.21"},
		{&net.TCPAddr{IP: net.ParseIP("::ffff:10.7.1.3"), Port: 1}, "10.7.1.3"},
		{&net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 1}, "fe80::1"},
		{nil, ""},
	}
	for _, tt := range tests {
		if got := clientIP(tt.addr); got != tt.want {
			t.Errorf("clientIP(%v) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}

// A matched answer lands in the activity log with the client, the matched
// name (the CNAME target here) and the rule's shunt; unmatched ones do not.
func TestForwarderRecordsActivity(t *testing.T) {
	s := newDoHServer(t, answerA(300, "192.0.2.7"))
	f := newTestForwarder(t, s)
	f.UpdateMatcher([]shunt.Entry{{Value: "example.org", Shunt: "Ex"}})

	f.queryOver(t, true, "www.example.org.", dns.TypeA)
	f.query(t, "www.example.org.", dns.TypeA) // cache hit counts too
	got, _, _ := f.Activity().Since(0, 10)
	if len(got) != 2 {
		t.Fatalf("activity: %+v", got)
	}
	e := got[1]
	if e.Client != "192.168.1.10" || e.Name != "www.example.org" || e.Shunt != "Ex" || e.Dim != len("www.") {
		t.Errorf("entry: %+v", e)
	}

	f.UpdateMatcher(nil)
	f.query(t, "www.example.org.", dns.TypeA)
	if got, _, _ := f.Activity().Since(2, 10); len(got) != 0 {
		t.Errorf("unmatched answer recorded: %+v", got)
	}

	// RecordAnswer (no client) is recorded without one.
	f.UpdateMatcher([]shunt.Entry{{Value: "full:cdn.example.net", Shunt: "Cdn"}})
	m := new(dns.Msg)
	m.Response = true
	m.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.Header{Name: "shop.example.com.", Class: dns.ClassINET, TTL: 60}, CNAME: rdata.CNAME{Target: "cdn.example.net."}},
		&dns.A{Hdr: dns.Header{Name: "cdn.example.net.", Class: dns.ClassINET, TTL: 60}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.9")}},
	}
	f.RecordAnswer(context.Background(), "shop.example.com", m)
	got, _, _ = f.Activity().Since(2, 10)
	if len(got) != 1 || got[0].Client != "" || got[0].Name != "cdn.example.net" || got[0].QName != "shop.example.com" || got[0].Shunt != "Cdn" {
		t.Fatalf("cname entry: %+v", got)
	}
}

func TestMatcherLookupShunt(t *testing.T) {
	m := NewMatcher()
	m.Update([]shunt.Entry{
		{Value: "example.com", Shunt: "A"},
		{Value: "example.com", Shunt: "B"}, // same rule later: first shunt wins
		{Value: "full:exact.org", Shunt: "B"},
		{Value: "keyword:tube", Shunt: "C"},
		{Value: `regexp:^api\d+\.x\.io$`, Shunt: "D"},
	})
	tests := []struct {
		name string
		want MatchInfo
		ok   bool
	}{
		{"www.example.com", MatchInfo{"A", MatchSuffix, "example.com"}, true},
		{"exact.org", MatchInfo{"B", MatchExact, "exact.org"}, true},
		{"m.youtube.com", MatchInfo{"C", MatchKeyword, "tube"}, true},
		{"api7.x.io", MatchInfo{"D", MatchRegexp, `^api\d+\.x\.io$`}, true},
		{"www.exact.org", MatchInfo{}, false},
	}
	for _, tt := range tests {
		got, ok := m.Lookup(tt.name)
		if ok != tt.ok || got != tt.want {
			t.Errorf("Lookup(%q) = %+v %v, want %+v %v", tt.name, got, ok, tt.want, tt.ok)
		}
		if m.Match(tt.name) != tt.ok {
			t.Errorf("Match(%q) disagrees with Lookup", tt.name)
		}
	}
}
