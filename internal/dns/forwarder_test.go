package dns

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"

	"github.com/egorlepa/netshunt/internal/shunt"
)

// fakeWriter captures one response. RemoteAddr decides UDP vs TCP handling;
// with a nil Conn the message is written length-prefixed (TCP framing).
type fakeWriter struct {
	udp bool
	buf bytes.Buffer
}

func (w *fakeWriter) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (w *fakeWriter) RemoteAddr() net.Addr {
	if w.udp {
		return &net.UDPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 5353}
	}
	return &net.TCPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 5353}
}
func (w *fakeWriter) Conn() net.Conn              { return nil }
func (w *fakeWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *fakeWriter) Close() error                { return nil }
func (w *fakeWriter) Session() *dns.Session       { return nil }
func (w *fakeWriter) Hijack()                     {}
func (w *fakeWriter) msg(t *testing.T) *dns.Msg {
	t.Helper()
	b := w.buf.Bytes()
	if len(b) < 2 {
		t.Fatal("no response written")
	}
	m := &dns.Msg{Data: b[2:]}
	if err := m.Unpack(); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	return m
}

type testForwarder struct {
	*Forwarder
	clock *fakeClock
	ipset *fakeIPSet
}

func newTestForwarder(t *testing.T, servers ...*dohServer) *testForwarder {
	t.Helper()
	tracker, ipset, _ := newTestTracker()
	f, err := NewForwarder(":0", []Upstream{{URL: "https://192.0.2.53/dns-query", SNI: "x"}}, tracker, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	// All httptest TLS servers share one certificate.
	pool := x509.NewCertPool()
	var ups []Upstream
	for _, s := range servers {
		pool.AddCert(s.Certificate())
		ups = append(ups, s.upstream())
	}
	if len(ups) > 0 {
		clients, err := newDoHClients(ups, withRootCAs(pool))
		if err != nil {
			t.Fatal(err)
		}
		f.upstreams.Store(&clients)
	}
	t.Cleanup(func() { closeClients(*f.upstreams.Load()) })
	cache, clock := newClockedCache(resolveCacheCap)
	f.cache = cache
	return &testForwarder{Forwarder: f, clock: clock, ipset: ipset}
}

var nextID uint16 = 100

// query sends one query through handleQuery and returns the response.
func (f *testForwarder) query(t *testing.T, name string, qtype uint16, opts ...func(*dns.Msg)) *dns.Msg {
	t.Helper()
	return f.queryOver(t, false, name, qtype, opts...)
}

func (f *testForwarder) queryOver(t *testing.T, udp bool, name string, qtype uint16, opts ...func(*dns.Msg)) *dns.Msg {
	t.Helper()
	q := dns.NewMsg(name, qtype)
	nextID++
	q.ID = nextID
	for _, o := range opts {
		o(q)
	}
	if err := q.Pack(); err != nil {
		t.Fatal(err)
	}
	w := &fakeWriter{udp: udp}
	f.handleQuery(context.Background(), w, &dns.Msg{Data: slices.Clone(q.Data)})
	resp := w.msg(t)
	if resp.ID != q.ID {
		t.Errorf("response ID = %d, want the client's %d", resp.ID, q.ID)
	}
	return resp
}

func answerTTL(t *testing.T, m *dns.Msg) uint32 {
	t.Helper()
	if len(m.Answer) == 0 {
		t.Fatalf("no answer: %v", m)
	}
	return m.Answer[0].Header().TTL
}

func TestForwarderCacheHitDecrementsTTL(t *testing.T) {
	s := newDoHServer(t, answerA(300, "192.0.2.1"))
	f := newTestForwarder(t, s)

	if ttl := answerTTL(t, f.query(t, "example.org.", dns.TypeA)); ttl != 300 {
		t.Errorf("first TTL = %d, want 300", ttl)
	}
	f.clock.advance(100 * time.Second)
	resp := f.query(t, "Example.ORG.", dns.TypeA)
	if s.hits.Load() != 1 {
		t.Errorf("upstream hits = %d, want 1 (second answer from cache)", s.hits.Load())
	}
	if ttl := answerTTL(t, resp); ttl != 200 {
		t.Errorf("cached TTL = %d, want 200", ttl)
	}
	if got := resp.Question[0].Header().Name; got != "Example.ORG." {
		t.Errorf("question = %q, want the client's spelling", got)
	}
	f.clock.advance(201 * time.Second)
	f.query(t, "example.org.", dns.TypeA)
	if s.hits.Load() != 2 {
		t.Errorf("expired entry served from cache")
	}
}

func TestForwarderCacheTTLClamp(t *testing.T) {
	low := newDoHServer(t, answerA(5, "192.0.2.1"))
	f := newTestForwarder(t, low)
	f.query(t, "low.example.org.", dns.TypeA)
	f.clock.advance(59 * time.Second)
	if ttl := answerTTL(t, f.query(t, "low.example.org.", dns.TypeA)); ttl != 1 {
		t.Errorf("TTL past its own value = %d, want floor 1", ttl)
	}
	if low.hits.Load() != 1 {
		t.Errorf("TTL 5 not clamped up to 60 s")
	}
	f.clock.advance(2 * time.Second)
	f.query(t, "low.example.org.", dns.TypeA)
	if low.hits.Load() != 2 {
		t.Errorf("entry kept past 60 s")
	}

	high := newDoHServer(t, answerA(7*86400, "192.0.2.2"))
	g := newTestForwarder(t, high)
	g.query(t, "high.example.org.", dns.TypeA)
	g.clock.advance(24*time.Hour - time.Second)
	g.query(t, "high.example.org.", dns.TypeA)
	if high.hits.Load() != 1 {
		t.Errorf("entry expired before 24 h")
	}
	g.clock.advance(2 * time.Second)
	g.query(t, "high.example.org.", dns.TypeA)
	if high.hits.Load() != 2 {
		t.Errorf("TTL 7 d not clamped down to 24 h")
	}
}

func TestCacheTTL(t *testing.T) {
	a := func(ttl uint32) dns.RR {
		return &dns.A{Hdr: dns.Header{Name: "x.", TTL: ttl, Class: dns.ClassINET}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}
	}
	soa := func(ttl uint32) dns.RR {
		return &dns.SOA{Hdr: dns.Header{Name: "x.", TTL: ttl, Class: dns.ClassINET}}
	}
	tests := []struct {
		name string
		m    *dns.Msg
		want time.Duration
	}{
		{"positive min", &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}, Answer: []dns.RR{a(600), a(120)}}, 120 * time.Second},
		{"positive clamp low", &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}, Answer: []dns.RR{a(1)}}, 60 * time.Second},
		{"positive clamp high", &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}, Answer: []dns.RR{a(1 << 30)}}, 24 * time.Hour},
		{"nodata", &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}, Ns: []dns.RR{soa(3600)}}, 60 * time.Second},
		{"nxdomain soa", &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeNameError}, Ns: []dns.RR{soa(900)}}, 900 * time.Second},
		{"nxdomain bare", &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeNameError}}, 60 * time.Second},
		{"servfail", &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeServerFailure}, Answer: []dns.RR{a(600)}}, 0},
		{"refused", &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeRefused}}, 0},
	}
	for _, tt := range tests {
		if got := cacheTTL(tt.m); got != tt.want {
			t.Errorf("%s: cacheTTL = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestForwarderCachesNXDomainAndNoData(t *testing.T) {
	nx := newDoHServer(t, rcodeOnly(dns.RcodeNameError))
	f := newTestForwarder(t, nx)
	for range 2 {
		if r := f.query(t, "nope.example.org.", dns.TypeA); r.Rcode != dns.RcodeNameError {
			t.Fatalf("rcode = %d, want NXDOMAIN", r.Rcode)
		}
	}
	if nx.hits.Load() != 1 {
		t.Errorf("NXDOMAIN not cached: hits = %d", nx.hits.Load())
	}

	nodata := newDoHServer(t, rcodeOnly(dns.RcodeSuccess))
	g := newTestForwarder(t, nodata)
	g.query(t, "example.org.", dns.TypeMX)
	g.clock.advance(59 * time.Second)
	g.query(t, "example.org.", dns.TypeMX)
	if nodata.hits.Load() != 1 {
		t.Errorf("NODATA not cached for 60 s")
	}
	g.clock.advance(2 * time.Second)
	g.query(t, "example.org.", dns.TypeMX)
	if nodata.hits.Load() != 2 {
		t.Errorf("NODATA kept past 60 s")
	}
}

func TestForwarderAllUpstreamsFailServfailNotCached(t *testing.T) {
	a := newDoHServer(t, rcodeOnly(dns.RcodeServerFailure))
	b := newDoHServer(t, rcodeOnly(dns.RcodeRefused))
	f := newTestForwarder(t, a, b)
	for range 2 {
		if r := f.query(t, "broken.example.org.", dns.TypeA); r.Rcode != dns.RcodeServerFailure {
			t.Fatalf("rcode = %d, want SERVFAIL", r.Rcode)
		}
	}
	if a.hits.Load() != 2 || b.hits.Load() != 2 {
		t.Errorf("SERVFAIL was cached: hits %d/%d", a.hits.Load(), b.hits.Load())
	}
}

func TestForwarderAAAAAnsweredLocally(t *testing.T) {
	s := newDoHServer(t, answerA(60, "192.0.2.1"))
	f := newTestForwarder(t, s)
	r := f.query(t, "example.org.", dns.TypeAAAA)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Errorf("AAAA = rcode %d, %d answers; want NODATA", r.Rcode, len(r.Answer))
	}
	if s.hits.Load() != 0 {
		t.Errorf("AAAA forwarded upstream")
	}
}

func TestForwarderUnqualifiedAndUndelegated(t *testing.T) {
	s := newDoHServer(t, answerA(60, "192.0.2.1"))
	f := newTestForwarder(t, s)
	for _, q := range []struct {
		name  string
		qtype uint16
	}{
		{"wpad.", dns.TypeA},
		{"printer.local.", dns.TypeA},
		{"printer.LOCAL.", dns.TypeTXT},
		{"router.lan.", dns.TypeA},
		{"10.1.168.192.in-addr.arpa.", dns.TypePTR},
		{"fritz.box.", dns.TypeA},
	} {
		if r := f.query(t, q.name, q.qtype); r.Rcode != dns.RcodeNameError {
			t.Errorf("%s %d: rcode = %d, want NXDOMAIN", q.name, q.qtype, r.Rcode)
		}
	}
	if s.hits.Load() != 0 {
		t.Errorf("local names forwarded upstream: %d", s.hits.Load())
	}

	// A single label is only unqualified for A/AAAA (dnscrypt-proxy rule);
	// a TLD's NS query and lookalike names still go upstream.
	f.query(t, "com.", dns.TypeNS)
	f.query(t, "notlocal.", dns.TypeTXT)
	f.query(t, "mylocal.org.", dns.TypeA)
	if s.hits.Load() != 3 {
		t.Errorf("upstream hits = %d, want 3", s.hits.Load())
	}
}

func TestIsUndelegated(t *testing.T) {
	if !slices.IsSorted(undelegatedZones) {
		t.Fatal("undelegatedZones must be sorted")
	}
	for name, want := range map[string]bool{
		"local": true, "a.b.local": true, "localhost": true, "x.home.arpa": true,
		"168.192.in-addr.arpa": true, "1.1.168.192.in-addr.arpa": true, "8.8.8.8.in-addr.arpa": false,
		"example.com": false, "notlocal": false, "": false, "mail": true, "mail.example.com": false,
	} {
		if got := isUndelegated(name); got != want {
			t.Errorf("isUndelegated(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestForwarderBlocklistTakesPrecedence(t *testing.T) {
	s := newDoHServer(t, answerA(60, "192.0.2.1"))
	f := newTestForwarder(t, s)
	f.Blocklist().Replace(func(add func(string)) {
		add("ads.example.org")
		add("tracker.local")
	})
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		if r := f.query(t, "x.ads.example.org.", qtype); r.Rcode != dns.RcodeNameError {
			t.Errorf("blocked type %d: rcode = %d, want blocklist NXDOMAIN", qtype, r.Rcode)
		}
	}
	f.SetBlockResponse(BlockZero)
	r := f.query(t, "x.ads.example.org.", dns.TypeAAAA)
	if len(r.Answer) != 1 || r.Answer[0].(*dns.AAAA).Addr != netip.IPv6Unspecified() {
		t.Errorf("blocked AAAA with zero response = %v, want ::", r.Answer)
	}
	if r := f.query(t, "tracker.local.", dns.TypeA); len(r.Answer) != 1 {
		t.Errorf("blocklist did not precede undelegated: %v", r)
	}
	if s.hits.Load() != 0 {
		t.Errorf("blocked names forwarded upstream")
	}
}

func TestForwarderTracksMatchedOnMissAndHit(t *testing.T) {
	s := newDoHServer(t, answerA(300, "192.0.2.7"))
	f := newTestForwarder(t, s)
	f.UpdateMatcher([]shunt.Entry{{Value: "example.org"}})

	f.query(t, "www.example.org.", dns.TypeA)
	if !f.ipset.has("192.0.2.7") {
		t.Fatal("matched answer not tracked")
	}
	f.TrackerRef().RemoveDomain(context.Background(), "www.example.org")
	if f.ipset.has("192.0.2.7") {
		t.Fatal("RemoveDomain left the IP")
	}
	f.query(t, "www.example.org.", dns.TypeA)
	if s.hits.Load() != 1 {
		t.Fatalf("second query not from cache")
	}
	if !f.ipset.has("192.0.2.7") {
		t.Errorf("cache hit for a matched domain not tracked")
	}

	f.query(t, "other.example.net.", dns.TypeA) // same IP, unmatched name
	if n := f.ipset.count("add 192.0.2.7"); n != 2 {
		t.Errorf("ipset adds = %d, want 2 (miss + re-add on hit; unmatched domain not tracked)", n)
	}
}

func TestForwarderAccumulatesSeedIPs(t *testing.T) {
	n := 0
	s := newDoHServer(t, func(q *dns.Msg) (*dns.Msg, time.Duration, int) {
		n++
		m, _, _ := answerA(60, fmt.Sprintf("192.0.2.%d", n))(q)
		return m, 0, 0
	})
	f := newTestForwarder(t, s)
	f.query(t, "rr.example.org.", dns.TypeA)
	f.clock.advance(61 * time.Second)
	f.query(t, "rr.example.org.", dns.TypeA)

	got := collect(f.ResolveCache())["rr.example.org"]
	if !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Errorf("seed IPs = %v, want both answers accumulated", got)
	}
}

func TestForwarderUDPTruncation(t *testing.T) {
	var ips []string
	for i := range 60 {
		ips = append(ips, fmt.Sprintf("198.51.100.%d", i))
	}
	s := newDoHServer(t, answerA(300, ips...))
	f := newTestForwarder(t, s)

	r := f.queryOver(t, true, "big.example.org.", dns.TypeA)
	if !r.Truncated || len(r.Answer) != 0 {
		t.Errorf("UDP without EDNS: truncated=%v answers=%d, want TC and no answers", r.Truncated, len(r.Answer))
	}
	r = f.queryOver(t, true, "big.example.org.", dns.TypeA, func(m *dns.Msg) { m.UDPSize = 1232 })
	if r.Truncated || len(r.Answer) != 60 {
		t.Errorf("UDP with EDNS 1232: truncated=%v answers=%d", r.Truncated, len(r.Answer))
	}
	if r.UDPSize != ednsUDPSize {
		t.Errorf("EDNS not mirrored: UDPSize = %d", r.UDPSize)
	}
	r = f.queryOver(t, false, "big.example.org.", dns.TypeA)
	if r.Truncated || len(r.Answer) != 60 || r.UDPSize != 0 {
		t.Errorf("TCP: truncated=%v answers=%d udpsize=%d", r.Truncated, len(r.Answer), r.UDPSize)
	}
}

func TestForwarderSetUpstreams(t *testing.T) {
	f := newTestForwarder(t)
	ups := []Upstream{{URL: "https://192.0.2.1/dns-query", SNI: "a.example"}}
	if err := f.SetUpstreams(ups); err != nil {
		t.Fatal(err)
	}
	before := *f.upstreams.Load()
	if err := f.SetUpstreams(ups); err != nil {
		t.Fatal(err)
	}
	if after := *f.upstreams.Load(); after[0] != before[0] {
		t.Errorf("unchanged list rebuilt its clients")
	}
	if err := f.SetUpstreams([]Upstream{{URL: "http://192.0.2.1/", SNI: "a"}}); err == nil {
		t.Errorf("invalid upstream accepted")
	}
	if got := f.UpstreamStats(); len(got) != 1 || got[0].Upstream != ups[0] {
		t.Errorf("failed SetUpstreams changed the list: %v", got)
	}
	if err := f.SetUpstreams(nil); err == nil {
		t.Errorf("empty upstream list accepted")
	}
}

// TestForwarderEndToEndUDP runs the real UDP/TCP servers so the raw query
// bytes (r.Data) forwarded upstream are the ones the dns.Server read.
func TestForwarderEndToEndUDP(t *testing.T) {
	s := newDoHServer(t, answerA(300, "192.0.2.9"))
	f := newTestForwarder(t, s)

	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.LocalAddr().String()
	_ = l.Close()
	f.listenAddr = addr
	if err := f.Start(); err != nil {
		t.Skipf("cannot start forwarder on %s: %v", addr, err)
	}
	defer f.Stop()

	c := dns.NewClient()
	for _, network := range []string{"udp", "tcp"} {
		q := dns.NewMsg("e2e.example.org.", dns.TypeA)
		q.UDPSize = 1232
		resp, _, err := c.Exchange(context.Background(), q, network, addr)
		if err != nil {
			t.Fatalf("%s exchange: %v", network, err)
		}
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).Addr.String() != "192.0.2.9" {
			t.Errorf("%s: resp = %v", network, resp)
		}
	}
	if s.hits.Load() != 1 {
		t.Errorf("upstream hits = %d, want 1 (TCP answer from cache)", s.hits.Load())
	}
}
