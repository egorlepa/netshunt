package dns

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"

	"github.com/egorlepa/netshunt/internal/shunt"
)

// BlockResponse is the kind of reply returned for a blocklisted query.
type BlockResponse int32

const (
	// BlockNXDomain replies with RCODE=NXDOMAIN.
	BlockNXDomain BlockResponse = iota
	// BlockNoData replies with RCODE=NOERROR and an empty answer section.
	BlockNoData
	// BlockZero replies with 0.0.0.0 / :: sinkhole addresses.
	BlockZero
)

// blockTTL is the TTL stamped on sinkhole / NXDOMAIN replies. Short so the
// client re-asks quickly after the user toggles a list.
const blockTTL = 60

// Forwarder is a DNS proxy that intercepts responses and tracks matched
// domains in the ipset. When IPv6 is enabled, both A and AAAA records are
// tracked. When disabled, AAAA records are stripped from matched responses
// to prevent IPv6 bypass.
type Forwarder struct {
	listenAddr string // e.g. ":53"
	upstream   string // e.g. "127.0.0.1:9153"
	ipv6       bool
	matcher    *Matcher
	blocklist  *Matcher
	blockResp  atomic.Int32
	tracker    *Tracker
	client     *dns.Client
	udpServer  *dns.Server
	tcpServer  *dns.Server
	logger     *slog.Logger
}

// NewForwarder creates a forwarder that listens on listenAddr and forwards
// queries to upstream.
func NewForwarder(listenAddr, upstream string, ipv6 bool, tracker *Tracker, logger *slog.Logger) *Forwarder {
	client := dns.NewClient()
	client.ReadTimeout = 5 * time.Second
	client.WriteTimeout = 5 * time.Second

	return &Forwarder{
		listenAddr: listenAddr,
		upstream:   upstream,
		ipv6:       ipv6,
		matcher:    NewMatcher(),
		blocklist:  NewMatcher(),
		tracker:    tracker,
		client:     client,
		logger:     logger,
	}
}

// Start begins serving DNS on UDP and TCP. It blocks until the servers are
// ready, then returns. Call Stop to shut down.
func (f *Forwarder) Start() error {
	handler := dns.HandlerFunc(f.handleQuery)

	f.udpServer = &dns.Server{
		Addr:    f.listenAddr,
		Net:     "udp",
		Handler: handler,
	}
	f.tcpServer = &dns.Server{
		Addr:    f.listenAddr,
		Net:     "tcp",
		Handler: handler,
	}

	udpReady := make(chan struct{})
	tcpReady := make(chan struct{})
	f.udpServer.NotifyStartedFunc = func(context.Context) { close(udpReady) }
	f.tcpServer.NotifyStartedFunc = func(context.Context) { close(tcpReady) }

	errCh := make(chan error, 2)
	go func() { errCh <- f.udpServer.ListenAndServe() }()
	go func() { errCh <- f.tcpServer.ListenAndServe() }()

	// Wait for both to be ready or for	 an error.
	for i := 0; i < 2; i++ {
		select {
		case <-udpReady:
			udpReady = nil
		case <-tcpReady:
			tcpReady = nil
		case err := <-errCh:
			f.Stop()
			return fmt.Errorf("dns forwarder start: %w", err)
		}
	}

	f.logger.Info("dns forwarder started", "listen", f.listenAddr, "upstream", f.upstream)
	return nil
}

// Stop gracefully shuts down both UDP and TCP servers.
func (f *Forwarder) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if f.udpServer != nil {
		f.udpServer.Shutdown(ctx)
	}
	if f.tcpServer != nil {
		f.tcpServer.Shutdown(ctx)
	}
}

// UpdateMatcher replaces the domain matching rules.
func (f *Forwarder) UpdateMatcher(entries []shunt.Entry) {
	f.matcher.Update(entries)
}

// Matcher returns the forwarder's matcher for external use.
func (f *Forwarder) Matcher() *Matcher {
	return f.matcher
}

// Blocklist returns the blocklist matcher. Callers drive the low-memory
// streaming build via Blocklist().ReplaceSuffixes(...). Reads are atomic.
func (f *Forwarder) Blocklist() *Matcher {
	return f.blocklist
}

// SetBlockResponse sets the response kind sent for blocklisted queries.
func (f *Forwarder) SetBlockResponse(r BlockResponse) {
	f.blockResp.Store(int32(r))
}

// Tracker returns the forwarder's tracker for external use.
func (f *Forwarder) TrackerRef() *Tracker {
	return f.tracker
}

func (f *Forwarder) handleQuery(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	if err := r.Unpack(); err != nil {
		f.logger.Debug("failed to unpack query", "error", err)
		return
	}

	if len(r.Question) == 0 {
		return
	}

	// Blocklist check — short-circuits before any upstream forward.
	qname := strings.TrimSuffix(r.Question[0].Header().Name, ".")
	qname = strings.ToLower(qname)
	if f.blocklist.Match(qname) {
		f.sendBlockResponse(w, r, qname)
		return
	}

	// Forward to upstream via UDP.
	resp, _, err := f.client.Exchange(ctx, r, "udp", f.upstream)
	if err != nil {
		f.logger.Debug("upstream exchange failed", "error", err)
		f.sendServFail(w, r)
		return
	}

	// If truncated over UDP, retry with TCP.
	if resp.Truncated {
		resp, _, err = f.client.Exchange(ctx, r, "tcp", f.upstream)
		if err != nil {
			f.logger.Debug("upstream TCP exchange failed", "error", err)
			f.sendServFail(w, r)
			return
		}
	}

	if f.matcher.Match(qname) {
		f.processMatchedResponse(ctx, qname, resp)
	}

	f.writeMsg(w, resp)
}

// processMatchedResponse extracts A records for tracking. When IPv6 is
// enabled, AAAA records are also tracked. When disabled, AAAA records are
// stripped from the response to prevent IPv6 bypass.
func (f *Forwarder) processMatchedResponse(ctx context.Context, domain string, resp *dns.Msg) {
	if f.ipv6 {
		for _, rr := range resp.Answer {
			switch a := rr.(type) {
			case *dns.A:
				f.tracker.Track(ctx, domain, a.Addr.String())
			case *dns.AAAA:
				f.tracker.Track(ctx, domain, a.Addr.String())
			}
		}
		return
	}

	// IPv6 disabled: track A records, strip AAAA records.
	filtered := resp.Answer[:0]
	for _, rr := range resp.Answer {
		switch a := rr.(type) {
		case *dns.A:
			f.tracker.Track(ctx, domain, a.Addr.String())
			filtered = append(filtered, rr)
		case *dns.AAAA:
			// Strip AAAA records.
		default:
			filtered = append(filtered, rr)
		}
	}
	resp.Answer = filtered
}

// writeMsg packs and writes a DNS message, logging any failure.
func (f *Forwarder) writeMsg(w dns.ResponseWriter, m *dns.Msg) {
	if err := m.Pack(); err != nil {
		f.logger.Debug("dns pack failed", "error", err)
		return
	}
	if _, err := io.Copy(w, m); err != nil {
		f.logger.Debug("dns write failed", "error", err)
	}
}

// sendBlockResponse crafts the configured reply for a blocklisted query.
// For NXDOMAIN / NoData: empty answer with the appropriate rcode.
// For Zero: an A or AAAA RR pointing at 0.0.0.0 / :: matching the query type.
// Other query types (MX, TXT, ...) on a blocked domain always get NoData
// to avoid leaking real records.
func (f *Forwarder) sendBlockResponse(w dns.ResponseWriter, r *dns.Msg, qname string) {
	f.writeMsg(w, blockReply(r, qname, BlockResponse(f.blockResp.Load())))
}

func blockReply(r *dns.Msg, qname string, kind BlockResponse) *dns.Msg {
	m := new(dns.Msg)
	m.ID = r.ID
	m.Response = true
	m.Question = r.Question
	m.RecursionDesired = r.RecursionDesired
	m.RecursionAvailable = true
	m.Rcode = dns.RcodeSuccess

	if kind == BlockNXDomain {
		m.Rcode = dns.RcodeNameError
		return m
	}

	if kind == BlockZero && len(r.Question) > 0 {
		qtype := dns.RRToType(r.Question[0])
		fqdn := qname
		if !strings.HasSuffix(fqdn, ".") {
			fqdn = fqdn + "."
		}
		switch qtype {
		case dns.TypeA:
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.Header{Name: fqdn, TTL: blockTTL, Class: dns.ClassINET},
				A:   rdata.A{Addr: netip.IPv4Unspecified()},
			}}
		case dns.TypeAAAA:
			m.Answer = []dns.RR{&dns.AAAA{
				Hdr:  dns.Header{Name: fqdn, TTL: blockTTL, Class: dns.ClassINET},
				AAAA: rdata.AAAA{Addr: netip.IPv6Unspecified()},
			}}
		}
	}
	// BlockNoData (and Zero for non-A/AAAA queries) → empty answer + NOERROR.
	return m
}

func (f *Forwarder) sendServFail(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.ID = r.ID
	m.Response = true
	m.Rcode = dns.RcodeServerFailure
	m.Question = r.Question
	m.RecursionDesired = r.RecursionDesired
	m.RecursionAvailable = true
	f.writeMsg(w, m)
}
