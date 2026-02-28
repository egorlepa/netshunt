package dns

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/egorlepa/netshunt/internal/shunt"
)

// Forwarder is a DNS proxy that intercepts responses and tracks matched
// domains in the ipset. When IPv6 is enabled, both A and AAAA records are
// tracked. When disabled, AAAA records are stripped from matched responses
// to prevent IPv6 bypass.
type Forwarder struct {
	listenAddr string // e.g. ":53"
	upstream   string // e.g. "127.0.0.1:9153"
	ipv6       bool
	matcher    *Matcher
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

	// Wait for both to be ready or for an error.
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

	// Extract queried domain (lowercase, without trailing dot).
	qname := strings.TrimSuffix(r.Question[0].Header().Name, ".")
	qname = strings.ToLower(qname)

	if f.matcher.Match(qname) {
		f.processMatchedResponse(ctx, qname, resp)
	}

	resp.Pack()
	io.Copy(w, resp)
}

// processMatchedResponse extracts A records for tracking. When IPv6 is
// enabled, AAAA records are also tracked. When disabled, AAAA records are
// stripped from the response to prevent IPv6 bypass.
func (f *Forwarder) processMatchedResponse(ctx context.Context, domain string, resp *dns.Msg) {
	if f.ipv6 {
		for _, rr := range resp.Answer {
			switch a := rr.(type) {
			case *dns.A:
				f.tracker.Track(ctx, domain, a.A.Addr.String())
			case *dns.AAAA:
				f.tracker.Track(ctx, domain, a.AAAA.Addr.String())
			}
		}
		return
	}

	// IPv6 disabled: track A records, strip AAAA records.
	filtered := resp.Answer[:0]
	for _, rr := range resp.Answer {
		switch a := rr.(type) {
		case *dns.A:
			f.tracker.Track(ctx, domain, a.A.Addr.String())
			filtered = append(filtered, rr)
		case *dns.AAAA:
			// Strip AAAA records.
		default:
			filtered = append(filtered, rr)
		}
	}
	resp.Answer = filtered
}

func (f *Forwarder) sendServFail(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.ID = r.ID
	m.Response = true
	m.Rcode = dns.RcodeServerFailure
	m.Question = r.Question
	m.RecursionDesired = r.RecursionDesired
	m.RecursionAvailable = true
	m.Pack()
	io.Copy(w, m)
}
