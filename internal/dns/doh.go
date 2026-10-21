package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/egorlepa/netshunt/internal/config"
)

// Upstream is a DNS-over-HTTPS resolver. URL must have an IP-literal host;
// SNI is used as the TLS server name and the HTTP Host header.
type Upstream struct {
	URL string
	SNI string
}

func (u Upstream) String() string { return u.URL + " (" + u.SNI + ")" }

// ConfigUpstreams returns the upstreams configured in c (the defaults when
// none are set).
func ConfigUpstreams(c config.DNSConfig) []Upstream {
	cfgUps := c.EffectiveUpstreams()
	ups := make([]Upstream, len(cfgUps))
	for i, u := range cfgUps {
		ups[i] = Upstream{URL: u.URL, SNI: u.SNI}
	}
	return ups
}

// UpstreamStats is a snapshot of one upstream's counters.
type UpstreamStats struct {
	Upstream    Upstream
	Queries     uint64 // requests sent
	Wins        uint64 // fan-out queries this upstream answered first
	Errors      uint64 // failed requests (cancelled losers are not errors)
	LastError   string
	LastErrorAt time.Time
}

// ErrBadRcode is wrapped by DoHClient.Exchange when the upstream answered
// with an rcode other than NOERROR or NXDOMAIN.
var ErrBadRcode = errors.New("upstream rcode")

const (
	dohContentType = "application/dns-message"
	// dohMaxResponse bounds the body read from an upstream: a DNS message
	// never exceeds 64 KiB.
	dohMaxResponse = dns.MaxMsgSize
	dohDialTimeout = 3 * time.Second
)

// DoHClient sends DNS queries to one DNS-over-HTTPS upstream with POST over
// a dedicated HTTP/2 transport (one keepalive connection).
type DoHClient struct {
	up        Upstream
	url       string
	transport *http.Transport
	client    *http.Client

	queries atomic.Uint64
	wins    atomic.Uint64
	errors  atomic.Uint64

	mu          sync.Mutex
	lastError   string
	lastErrorAt time.Time
}

// dohOptions holds construction knobs; rootCAs is only set by tests.
type dohOptions struct {
	rootCAs *x509.CertPool
}

// DoHOption customises a DoHClient.
type DoHOption func(*dohOptions)

// NewDoHClient validates up and builds a client with its own transport.
func NewDoHClient(up Upstream, opts ...DoHOption) (*DoHClient, error) {
	var o dohOptions
	for _, opt := range opts {
		opt(&o)
	}
	u, err := url.Parse(up.URL)
	if err != nil {
		return nil, fmt.Errorf("doh upstream %q: %w", up.URL, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("doh upstream %q: scheme must be https", up.URL)
	}
	if _, err := netip.ParseAddr(u.Hostname()); err != nil {
		return nil, fmt.Errorf("doh upstream %q: host must be an IP address", up.URL)
	}
	if strings.TrimSpace(up.SNI) == "" {
		return nil, fmt.Errorf("doh upstream %q: empty sni", up.URL)
	}

	dialer := &net.Dialer{Timeout: dohDialTimeout, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy:       nil, // never route resolver traffic through an env proxy
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			ServerName: up.SNI,
			MinVersion: tls.VersionTLS12,
			RootCAs:    o.rootCAs,
		},
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    dohDialTimeout,
		MaxIdleConns:           1,
		MaxIdleConnsPerHost:    1,
		IdleConnTimeout:        2 * time.Minute,
		MaxResponseHeaderBytes: 16 << 10,
		HTTP2: &http.HTTP2Config{
			// Detect a dead connection (WAN flap) instead of timing out
			// queries on it until the kernel gives up.
			SendPingTimeout: 30 * time.Second,
			PingTimeout:     5 * time.Second,
		},
	}
	return &DoHClient{
		up:        up,
		url:       u.String(),
		transport: tr,
		client:    &http.Client{Transport: tr},
	}, nil
}

// Upstream returns the upstream this client talks to.
func (c *DoHClient) Upstream() Upstream { return c.up }

// Exchange sends the packed query q.Data and returns the unpacked response.
// q must already be packed (q.Data set) and is never modified, so one query
// can be sent to several clients concurrently. The response is valid only
// if the HTTP status is 200, it unpacks, its ID and question match q, and
// its rcode is NOERROR or NXDOMAIN; anything else is an error.
func (c *DoHClient) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	c.queries.Add(1)
	resp, err := c.exchange(ctx, q)
	if err != nil {
		// A request cancelled because another upstream won is not a failure.
		if !errors.Is(ctx.Err(), context.Canceled) {
			c.recordError(err)
		}
		return nil, err
	}
	return resp, nil
}

func (c *DoHClient) exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if len(q.Data) == 0 {
		return nil, errors.New("doh: query not packed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(q.Data))
	if err != nil {
		return nil, err
	}
	req.Host = c.up.SNI
	req.Header.Set("Content-Type", dohContentType)
	req.Header.Set("Accept", dohContentType)

	hresp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = hresp.Body.Close() }()
	if hresp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(hresp.Body, 4<<10))
		return nil, fmt.Errorf("doh: http status %d", hresp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(hresp.Body, dohMaxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("doh: read body: %w", err)
	}
	if len(body) > dohMaxResponse {
		return nil, errors.New("doh: response too large")
	}

	resp := &dns.Msg{Data: body}
	if err := resp.Unpack(); err != nil {
		return nil, fmt.Errorf("doh: unpack: %w", err)
	}
	if err := validateResponse(q, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// validateResponse checks that resp answers q with a usable rcode.
func validateResponse(q, resp *dns.Msg) error {
	if !resp.Response {
		return errors.New("doh: not a response")
	}
	if resp.ID != q.ID {
		return fmt.Errorf("doh: id mismatch %d != %d", resp.ID, q.ID)
	}
	if len(q.Question) > 0 {
		if len(resp.Question) == 0 {
			return errors.New("doh: response without question")
		}
		qh, rh := q.Question[0].Header(), resp.Question[0].Header()
		if !strings.EqualFold(qh.Name, rh.Name) || qh.Class != rh.Class ||
			dns.RRToType(q.Question[0]) != dns.RRToType(resp.Question[0]) {
			return errors.New("doh: question mismatch")
		}
	}
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return fmt.Errorf("%w %s", ErrBadRcode, dns.RcodeToString[resp.Rcode])
	}
	return nil
}

func (c *DoHClient) recordError(err error) {
	c.errors.Add(1)
	c.mu.Lock()
	c.lastError = err.Error()
	c.lastErrorAt = time.Now()
	c.mu.Unlock()
}

// Stats returns a snapshot of the client's counters.
func (c *DoHClient) Stats() UpstreamStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return UpstreamStats{
		Upstream:    c.up,
		Queries:     c.queries.Load(),
		Wins:        c.wins.Load(),
		Errors:      c.errors.Load(),
		LastError:   c.lastError,
		LastErrorAt: c.lastErrorAt,
	}
}

// Close drops the client's idle connections. In-flight requests finish on
// their own; the client must not be used afterwards.
func (c *DoHClient) Close() {
	c.transport.CloseIdleConnections()
}

// upstreamTimeout bounds one fan-out query across all upstreams. A
// variable only so tests can shorten it.
var upstreamTimeout = 3 * time.Second

type exchangeResult struct {
	i    int
	resp *dns.Msg
	err  error
}

// exchangeAll sends packed query q to every client concurrently and returns
// the first valid response and its client; the other requests are
// cancelled. When every client fails it returns a nil response and one
// error per client (in client order). Individual failures are logged at
// Debug.
func exchangeAll(ctx context.Context, clients []*DoHClient, q *dns.Msg, logger *slog.Logger) (*dns.Msg, *DoHClient, []error) {
	if len(clients) == 0 {
		return nil, nil, []error{errors.New("no upstreams configured")}
	}
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()

	ch := make(chan exchangeResult, len(clients)) // buffered: losers never block
	for i, c := range clients {
		go func() {
			resp, err := c.Exchange(ctx, q)
			ch <- exchangeResult{i: i, resp: resp, err: err}
		}()
	}
	errs := make([]error, len(clients))
	for range clients {
		r := <-ch
		if r.err == nil {
			cancel()
			clients[r.i].wins.Add(1)
			return r.resp, clients[r.i], nil
		}
		logger.Debug("dns upstream failed", "upstream", clients[r.i].up.SNI, "error", r.err)
		errs[r.i] = r.err
	}
	return nil, nil, errs
}
