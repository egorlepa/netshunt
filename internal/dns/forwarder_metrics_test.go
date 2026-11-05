package dns

import (
	"testing"

	"codeberg.org/miekg/dns"
)

// Every way handleQuery answers increments exactly its result label, and
// only the upstream path (answered or failed) is timed.
func TestForwarderQueryResultCounters(t *testing.T) {
	ok := newDoHServer(t, answerA(300, "192.0.2.1"))
	f := newTestForwarder(t, ok)
	f.Blocklist().Replace(func(add func([]byte)) { add([]byte("ads.example.org")) })

	want := map[QueryResult]uint64{}
	check := func(step string) {
		t.Helper()
		for _, r := range QueryResults() {
			if got := f.QueryCount(r); got != want[r] {
				t.Errorf("%s: %s = %d, want %d", step, r, got, want[r])
			}
		}
		h := f.UpstreamDuration()
		if wantN := want[ResultUpstream] + want[ResultServFail]; h.Count != wantN {
			t.Errorf("%s: upstream histogram count = %d, want %d", step, h.Count, wantN)
		}
	}

	f.query(t, "x.ads.example.org.", dns.TypeA)
	want[ResultBlocked]++
	check("blocked")

	f.query(t, "example.org.", dns.TypeAAAA)
	want[ResultAAAANoData]++
	check("aaaa")

	f.query(t, "wpad.", dns.TypeA)
	f.query(t, "printer.local.", dns.TypeA)
	want[ResultLocalNXDomain] += 2
	check("local")

	f.query(t, "example.org.", dns.TypeA)
	want[ResultUpstream]++
	check("upstream")

	f.query(t, "example.org.", dns.TypeA)
	want[ResultCacheHit]++
	check("cache hit")

	bad := newDoHServer(t, rcodeOnly(dns.RcodeServerFailure))
	g := newTestForwarder(t, bad)
	g.query(t, "broken.example.org.", dns.TypeA)
	if g.QueryCount(ResultServFail) != 1 || g.QueryCount(ResultUpstream) != 0 {
		t.Errorf("servfail = %d, upstream = %d", g.QueryCount(ResultServFail), g.QueryCount(ResultUpstream))
	}
	if h := g.UpstreamDuration(); h.Count != 1 || h.Cumulative[len(h.Cumulative)-1] != 1 || len(h.Bounds) != len(UpstreamDurationBuckets) {
		t.Errorf("servfail histogram = %+v", h)
	}
}
