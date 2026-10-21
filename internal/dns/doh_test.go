package dns

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// withRootCAs trusts pool instead of the system roots. Test-only: the
// production code never sets it.
func withRootCAs(pool *x509.CertPool) DoHOption {
	return func(o *dohOptions) { o.rootCAs = pool }
}

// dohServer is an HTTP/2 TLS test server speaking application/dns-message.
type dohServer struct {
	*httptest.Server
	hits      atomic.Int64
	cancelled atomic.Int64 // requests whose context was cancelled by the client
	lastHost  atomic.Value
	lastProto atomic.Int64
}

// dohHandler builds the answer for q; delay is applied first and aborted
// when the client cancels. status 0 means 200.
type dohHandler func(q *dns.Msg) (resp *dns.Msg, delay time.Duration, status int)

func newDoHServer(t *testing.T, h dohHandler) *dohServer {
	t.Helper()
	s := &dohServer{}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.lastHost.Store(r.Host)
		s.lastProto.Store(int64(r.ProtoMajor))
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != dohContentType || r.Header.Get("Accept") != dohContentType {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		q := &dns.Msg{Data: body}
		if err := q.Unpack(); err != nil {
			http.Error(w, "bad dns", http.StatusBadRequest)
			return
		}
		resp, delay, status := h(q)
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				s.cancelled.Add(1)
				return
			}
		}
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if err := resp.Pack(); err != nil {
			t.Errorf("pack test response: %v", err)
			return
		}
		w.Header().Set("Content-Type", dohContentType)
		_, _ = w.Write(resp.Data)
	}))
	s.EnableHTTP2 = true
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func (s *dohServer) upstream() Upstream {
	return Upstream{URL: s.URL + "/dns-query", SNI: "example.com"}
}

func (s *dohServer) client(t *testing.T) *DoHClient {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	c, err := NewDoHClient(s.upstream(), withRootCAs(pool))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// answerA replies with one A record per ip, all with the given TTL.
func answerA(ttl uint32, ips ...string) dohHandler {
	return func(q *dns.Msg) (*dns.Msg, time.Duration, int) {
		m := replyTo(q, dns.RcodeSuccess)
		for _, ip := range ips {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.Header{Name: q.Question[0].Header().Name, TTL: ttl, Class: dns.ClassINET},
				A:   rdata.A{Addr: netip.MustParseAddr(ip)},
			})
		}
		return m, 0, 0
	}
}

func rcodeOnly(rcode uint16) dohHandler {
	return func(q *dns.Msg) (*dns.Msg, time.Duration, int) { return replyTo(q, rcode), 0, 0 }
}

func delayed(d time.Duration, h dohHandler) dohHandler {
	return func(q *dns.Msg) (*dns.Msg, time.Duration, int) {
		m, _, st := h(q)
		return m, d, st
	}
}

func replyTo(q *dns.Msg, rcode uint16) *dns.Msg {
	m := new(dns.Msg)
	m.ID = q.ID
	m.Response = true
	m.RecursionDesired = q.RecursionDesired
	m.RecursionAvailable = true
	m.Question = q.Question
	m.Rcode = rcode
	return m
}

func packedQuery(t *testing.T, name string, qtype uint16) *dns.Msg {
	t.Helper()
	q := dns.NewMsg(name, qtype)
	q.ID = 4242
	if err := q.Pack(); err != nil {
		t.Fatal(err)
	}
	return q
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestDoHExchange(t *testing.T) {
	s := newDoHServer(t, answerA(300, "192.0.2.1"))
	c := s.client(t)

	resp, err := c.Exchange(context.Background(), packedQuery(t, "example.org.", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).Addr.String() != "192.0.2.1" {
		t.Errorf("answer = %v", resp.Answer)
	}
	if got := s.lastHost.Load(); got != "example.com" {
		t.Errorf("Host header = %v, want the SNI", got)
	}
	if s.lastProto.Load() != 2 {
		t.Errorf("proto = HTTP/%d, want HTTP/2", s.lastProto.Load())
	}
	if st := c.Stats(); st.Queries != 1 || st.Errors != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestDoHExchangeInvalidResponses(t *testing.T) {
	tests := []struct {
		name string
		h    dohHandler
		want string
	}{
		{"http error", func(q *dns.Msg) (*dns.Msg, time.Duration, int) { return nil, 0, http.StatusBadGateway }, "http status 502"},
		{"servfail", rcodeOnly(dns.RcodeServerFailure), "upstream rcode"},
		{"refused", rcodeOnly(dns.RcodeRefused), "upstream rcode"},
		{"id mismatch", func(q *dns.Msg) (*dns.Msg, time.Duration, int) {
			m := replyTo(q, dns.RcodeSuccess)
			m.ID++
			return m, 0, 0
		}, "id mismatch"},
		{"question mismatch", func(q *dns.Msg) (*dns.Msg, time.Duration, int) {
			m := replyTo(q, dns.RcodeSuccess)
			m.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "other.org.", Class: dns.ClassINET}}}
			return m, 0, 0
		}, "question mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newDoHServer(t, tt.h).client(t)
			_, err := c.Exchange(context.Background(), packedQuery(t, "example.org.", dns.TypeA))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
			if st := c.Stats(); st.Errors != 1 || st.LastError == "" || st.LastErrorAt.IsZero() {
				t.Errorf("stats = %+v, want one recorded error", st)
			}
		})
	}
}

func TestDoHExchangeMalformedBody(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not dns"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c, err := NewDoHClient(Upstream{URL: srv.URL, SNI: "example.com"}, withRootCAs(pool))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Exchange(context.Background(), packedQuery(t, "example.org.", dns.TypeA)); err == nil {
		t.Fatal("malformed body accepted")
	}
}

func TestDoHNXDomainIsValid(t *testing.T) {
	c := newDoHServer(t, rcodeOnly(dns.RcodeNameError)).client(t)
	resp, err := c.Exchange(context.Background(), packedQuery(t, "nope.example.org.", dns.TypeA))
	if err != nil || resp.Rcode != dns.RcodeNameError {
		t.Fatalf("resp = %v, err = %v", resp, err)
	}
}

func TestDoHUntrustedCertRejected(t *testing.T) {
	s := newDoHServer(t, answerA(60, "192.0.2.1"))
	c, err := NewDoHClient(s.upstream()) // system roots: the test cert is not trusted
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Exchange(context.Background(), packedQuery(t, "example.org.", dns.TypeA)); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}

func TestNewDoHClientValidation(t *testing.T) {
	for _, u := range []Upstream{
		{URL: "http://8.8.8.8/dns-query", SNI: "dns.google"},
		{URL: "https://dns.google/dns-query", SNI: "dns.google"},
		{URL: "https://8.8.8.8/dns-query", SNI: ""},
	} {
		if _, err := NewDoHClient(u); err == nil {
			t.Errorf("NewDoHClient(%v) accepted", u)
		}
	}
}

func TestExchangeAllFastWinsSlowCancelled(t *testing.T) {
	slow := newDoHServer(t, delayed(2*time.Second, answerA(60, "192.0.2.2")))
	// The fast one still takes a moment so the slow request is surely
	// in its handler when the winner cancels it.
	fast := newDoHServer(t, delayed(300*time.Millisecond, answerA(60, "192.0.2.1")))
	clients := []*DoHClient{slow.client(t), fast.client(t)}

	start := time.Now()
	resp, winner, errs := exchangeAll(context.Background(), clients, packedQuery(t, "example.org.", dns.TypeA), discardLogger())
	if resp == nil {
		t.Fatalf("no answer: %v", errs)
	}
	if winner != clients[1] || resp.Answer[0].(*dns.A).Addr.String() != "192.0.2.1" {
		t.Errorf("winner = %v, answer %v", winner.Upstream(), resp.Answer)
	}
	if time.Since(start) > time.Second {
		t.Errorf("fan-out waited for the slow upstream: %v", time.Since(start))
	}
	waitFor(t, func() bool { return slow.cancelled.Load() == 1 }, "slow request cancelled")
	if st := clients[0].Stats(); st.Errors != 0 || st.Wins != 0 || st.Queries != 1 {
		t.Errorf("slow stats = %+v: a cancelled loser is not an error", st)
	}
	if st := clients[1].Stats(); st.Wins != 1 {
		t.Errorf("fast stats = %+v", st)
	}
}

func TestExchangeAllServfailLoses(t *testing.T) {
	bad := newDoHServer(t, rcodeOnly(dns.RcodeServerFailure))
	good := newDoHServer(t, delayed(200*time.Millisecond, answerA(60, "192.0.2.3")))
	clients := []*DoHClient{bad.client(t), good.client(t)}

	resp, winner, errs := exchangeAll(context.Background(), clients, packedQuery(t, "example.org.", dns.TypeA), discardLogger())
	if resp == nil || winner != clients[1] {
		t.Fatalf("resp = %v, errs = %v", resp, errs)
	}
	if clients[0].Stats().Errors != 1 {
		t.Errorf("SERVFAIL not counted as an error: %+v", clients[0].Stats())
	}
}

func TestExchangeAllAllFail(t *testing.T) {
	a := newDoHServer(t, rcodeOnly(dns.RcodeServerFailure))
	b := newDoHServer(t, func(q *dns.Msg) (*dns.Msg, time.Duration, int) { return nil, 0, http.StatusInternalServerError })
	clients := []*DoHClient{a.client(t), b.client(t)}

	resp, winner, errs := exchangeAll(context.Background(), clients, packedQuery(t, "example.org.", dns.TypeA), discardLogger())
	if resp != nil || winner != nil {
		t.Fatalf("got an answer from failing upstreams")
	}
	if len(errs) != 2 || !errors.Is(errs[0], ErrBadRcode) || !strings.Contains(errs[1].Error(), "500") {
		t.Errorf("errs = %v", errs)
	}
}

func TestExchangeAllTimeout(t *testing.T) {
	old := upstreamTimeout
	upstreamTimeout = 300 * time.Millisecond
	defer func() { upstreamTimeout = old }()

	hang := newDoHServer(t, delayed(5*time.Second, answerA(60, "192.0.2.4")))
	clients := []*DoHClient{hang.client(t)}

	start := time.Now()
	resp, _, errs := exchangeAll(context.Background(), clients, packedQuery(t, "example.org.", dns.TypeA), discardLogger())
	elapsed := time.Since(start)
	if resp != nil {
		t.Fatal("answer from a hanging upstream")
	}
	if elapsed > 2*time.Second {
		t.Errorf("timeout not honoured: %v", elapsed)
	}
	if !errors.Is(errs[0], context.DeadlineExceeded) {
		t.Errorf("err = %v, want deadline exceeded", errs[0])
	}
	if st := clients[0].Stats(); st.Errors != 1 {
		t.Errorf("timeout not counted as an error: %+v", st)
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProbeUpstream(t *testing.T) {
	s := newDoHServer(t, answerA(60, "192.0.2.1"))
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	rtt, err := ProbeUpstream(context.Background(), s.upstream(), withRootCAs(pool))
	if err != nil || rtt <= 0 {
		t.Fatalf("rtt = %v, err = %v", rtt, err)
	}
	bad := newDoHServer(t, rcodeOnly(dns.RcodeServerFailure))
	if _, err := ProbeUpstream(context.Background(), bad.upstream(), withRootCAs(pool)); !errors.Is(err, ErrBadRcode) {
		t.Errorf("SERVFAIL probe err = %v", err)
	}
}
