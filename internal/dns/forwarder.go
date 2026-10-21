package dns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
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

// Forwarder is a DNS proxy that resolves through DNS-over-HTTPS upstreams,
// caches responses, and tracks the IPs of shunt-matched domains in the
// ipset. AAAA queries are answered locally with an empty answer: netshunt
// routes only IPv4, and an AAAA answer would let clients bypass the proxy.
type Forwarder struct {
	listenAddr string // e.g. ":53"
	upstreams  atomic.Pointer[[]*DoHClient]
	upMu       sync.Mutex // serialises SetUpstreams
	matcher    *Matcher
	blocklist  *BlocklistMatcher
	blockResp  atomic.Int32
	tracker    *Tracker
	cache      *ResolveCache
	udpServer  *dns.Server
	tcpServer  *dns.Server
	logger     *slog.Logger
}

// resolveCacheCap bounds the number of cached domains. Tuned for
// home-router workloads.
const resolveCacheCap = 20_000

// NewForwarder creates a forwarder that listens on listenAddr and resolves
// through upstreams (see SetUpstreams).
func NewForwarder(listenAddr string, upstreams []Upstream, tracker *Tracker, logger *slog.Logger) (*Forwarder, error) {
	f := &Forwarder{
		listenAddr: listenAddr,
		matcher:    NewMatcher(),
		blocklist:  NewBlocklistMatcher(),
		tracker:    tracker,
		cache:      NewResolveCache(resolveCacheCap),
		logger:     logger,
	}
	clients, err := newDoHClients(upstreams)
	if err != nil {
		return nil, err
	}
	f.upstreams.Store(&clients)
	return f, nil
}

func newDoHClients(upstreams []Upstream, opts ...DoHOption) ([]*DoHClient, error) {
	if len(upstreams) == 0 {
		return nil, errors.New("no dns upstreams")
	}
	clients := make([]*DoHClient, 0, len(upstreams))
	for _, u := range upstreams {
		c, err := NewDoHClient(u, opts...)
		if err != nil {
			closeClients(clients)
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, nil
}

func closeClients(clients []*DoHClient) {
	for _, c := range clients {
		c.Close()
	}
}

// SetUpstreams replaces the upstream list atomically. Queries already in
// flight finish on the old clients, whose idle connections are closed.
func (f *Forwarder) SetUpstreams(upstreams []Upstream) error {
	clients, err := newDoHClients(upstreams)
	if err != nil {
		return err
	}
	f.upMu.Lock()
	defer f.upMu.Unlock()
	if old := f.upstreams.Load(); old != nil {
		if sameUpstreams(*old, upstreams) {
			// Nothing changed: keep the warm connections.
			closeClients(clients)
			return nil
		}
		f.upstreams.Store(&clients)
		closeClients(*old)
	} else {
		f.upstreams.Store(&clients)
	}
	f.logger.Info("dns upstreams updated", "upstreams", upstreamNames(clients))
	return nil
}

func sameUpstreams(clients []*DoHClient, ups []Upstream) bool {
	if len(clients) != len(ups) {
		return false
	}
	for i, c := range clients {
		if c.up != ups[i] {
			return false
		}
	}
	return true
}

func upstreamNames(clients []*DoHClient) []string {
	names := make([]string, len(clients))
	for i, c := range clients {
		names[i] = c.up.String()
	}
	return names
}

// UpstreamStats returns a snapshot of the current upstreams' counters.
func (f *Forwarder) UpstreamStats() []UpstreamStats {
	clients := *f.upstreams.Load()
	out := make([]UpstreamStats, len(clients))
	for i, c := range clients {
		out[i] = c.Stats()
	}
	return out
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

	f.logger.Info("dns forwarder started", "listen", f.listenAddr, "upstreams", upstreamNames(*f.upstreams.Load()))
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
	closeClients(*f.upstreams.Load())
}

// UpdateMatcher replaces the domain matching rules and returns the domain
// entries that could not be applied.
func (f *Forwarder) UpdateMatcher(entries []shunt.Entry) []shunt.Entry {
	return f.matcher.Update(entries)
}

// Matcher returns the forwarder's matcher for external use.
func (f *Forwarder) Matcher() *Matcher {
	return f.matcher
}

// Blocklist returns the blocklist matcher. Callers drive the low-memory
// streaming build via Blocklist().Replace(...). Reads are atomic.
func (f *Forwarder) Blocklist() *BlocklistMatcher {
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

// ResolveCache returns the forwarder's recent-resolutions cache for the
// reconciler to seed ipset entries when a new shunt rule is added.
func (f *Forwarder) ResolveCache() *ResolveCache {
	return f.cache
}

func (f *Forwarder) handleQuery(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	if err := r.Unpack(); err != nil {
		f.logger.Debug("failed to unpack query", "error", err)
		return
	}

	if len(r.Question) == 0 {
		return
	}

	q := r.Question[0]
	qtype := dns.RRToType(q)
	qclass := q.Header().Class
	qname := strings.ToLower(strings.TrimSuffix(q.Header().Name, "."))

	// Blocklist check: short-circuits before anything else.
	if f.blocklist.Match(qname) {
		f.sendBlockResponse(w, r, qname)
		return
	}

	// IPv4-only: never resolve AAAA, so clients cannot bypass the proxy.
	if qtype == dns.TypeAAAA {
		f.writeMsg(w, blockReply(r, qname, BlockNoData))
		return
	}

	if isUnqualified(qname, qtype, qclass) {
		f.logger.Debug("dns answered locally", "name", qname, "reason", "unqualified")
		f.writeMsg(w, blockReply(r, qname, BlockNXDomain))
		return
	}
	if isUndelegated(qname) {
		f.logger.Debug("dns answered locally", "name", qname, "reason", "undelegated")
		f.writeMsg(w, blockReply(r, qname, BlockNXDomain))
		return
	}

	cacheable := r.Opcode == dns.OpcodeQuery && qclass == dns.ClassINET
	if cacheable {
		if resp := f.cachedResponse(qname, qtype); resp != nil {
			f.trackMatched(ctx, qname, resp)
			f.reply(w, r, resp)
			return
		}
	}

	// Send the client's wire message as-is (EDNS and DO bit included) to
	// every upstream; the same bytes are shared by all requests.
	query := &dns.Msg{Data: slices.Clone(r.Data)}
	query.ID = r.ID
	query.Question = r.Question
	start := time.Now()
	resp, winner, errs := exchangeAll(ctx, *f.upstreams.Load(), query, f.logger)
	if resp == nil {
		msgs := make([]string, len(errs))
		for i, err := range errs {
			msgs[i] = err.Error()
		}
		f.logger.Warn("all dns upstreams failed", "name", qname, "type", dns.TypeToString[qtype], "errors", strings.Join(msgs, "; "))
		f.sendServFail(w, r)
		return
	}
	if f.logger.Enabled(ctx, slog.LevelDebug) {
		st := winner.Stats()
		f.logger.Debug("dns upstream answered", "name", qname, "type", dns.TypeToString[qtype],
			"upstream", winner.up.SNI, "rtt", time.Since(start).Round(time.Millisecond),
			"queries", st.Queries, "wins", st.Wins)
	}

	if cacheable {
		f.storeResponse(qname, qtype, resp)
	}
	f.trackMatched(ctx, qname, resp)

	// Remember every successful A-resolve regardless of shunt match, so that
	// a later shunt mutation can retroactively seed the ipset for IPs the
	// client already cached.
	f.cacheResolved(qname, resp)

	f.reply(w, r, resp)
}

// Response cache TTL bounds. NODATA has no TTL of its own here.
const (
	minCacheTTL    = 60 * time.Second
	maxCacheTTL    = 24 * time.Hour
	noDataCacheTTL = 60 * time.Second
)

// cacheTTL returns how long resp may be cached: NODATA for noDataCacheTTL,
// otherwise the minimum TTL over the answer and authority records clamped
// to [minCacheTTL, maxCacheTTL]; 0 for rcodes that are never cached.
func cacheTTL(resp *dns.Msg) time.Duration {
	switch resp.Rcode {
	case dns.RcodeSuccess:
		if len(resp.Answer) == 0 {
			return noDataCacheTTL
		}
	case dns.RcodeNameError:
	default:
		return 0
	}
	minTTL := uint32(math.MaxUint32)
	for _, rr := range resp.Answer {
		minTTL = min(minTTL, rr.Header().TTL)
	}
	for _, rr := range resp.Ns {
		minTTL = min(minTTL, rr.Header().TTL)
	}
	if minTTL == math.MaxUint32 {
		return minCacheTTL
	}
	return min(max(time.Duration(minTTL)*time.Second, minCacheTTL), maxCacheTTL)
}

// storeResponse caches the upstream's packed response (resp.Data, before
// any client-specific rewriting).
func (f *Forwarder) storeResponse(qname string, qtype uint16, resp *dns.Msg) {
	if ttl := cacheTTL(resp); ttl > 0 {
		f.cache.StoreResponse(qname, qtype, resp.Data, ttl)
	}
}

// cachedResponse returns the live cached response for (qname, qtype) with
// TTLs decremented by the time spent in the cache (floor 1), or nil.
func (f *Forwarder) cachedResponse(qname string, qtype uint16) *dns.Msg {
	packed, age, ok := f.cache.LookupResponse(qname, qtype)
	if !ok {
		return nil
	}
	resp := &dns.Msg{Data: packed}
	if err := resp.Unpack(); err != nil {
		f.logger.Debug("cached response unpack failed", "name", qname, "error", err)
		return nil
	}
	elapsed := uint32(age / time.Second)
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, rr := range section {
			h := rr.Header()
			if h.TTL > elapsed {
				h.TTL -= elapsed
			} else {
				h.TTL = 1
			}
		}
	}
	return resp
}

// ednsUDPSize is the UDP payload size netshunt advertises to EDNS clients;
// maxUDPReply caps what it will send over UDP regardless of the client's
// advertised size.
const (
	ednsUDPSize = 1232
	maxUDPReply = 4096
)

// reply rewrites resp for client query r (ID, question spelling, EDNS
// mirroring the client) and writes it, truncating to the client's UDP
// limit so it retries over TCP.
func (f *Forwarder) reply(w dns.ResponseWriter, r, resp *dns.Msg) {
	resp.ID = r.ID
	resp.Question = r.Question
	resp.Pseudo = nil
	resp.CompactAnswers, resp.Delegation = false, false
	clientEDNS := r.UDPSize > 0 || r.Security || len(r.Pseudo) > 0
	if clientEDNS {
		resp.UDPSize = ednsUDPSize
		resp.Security = r.Security
	} else {
		resp.UDPSize = 0
		resp.Security = false
	}
	if err := resp.Pack(); err != nil {
		f.logger.Debug("dns pack failed", "error", err)
		f.sendServFail(w, r)
		return
	}

	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
		limit := dns.MinMsgSize
		if clientEDNS {
			limit = min(max(int(r.UDPSize), dns.MinMsgSize), maxUDPReply)
		}
		if len(resp.Data) > limit {
			tc := new(dns.Msg)
			tc.MsgHeader = resp.MsgHeader
			tc.Truncated = true
			tc.Question = r.Question
			resp = tc
		}
	}
	f.writeMsg(w, resp)
}

// cacheResolved adds the A records of a successful resolution to the
// domain's accumulated seeding IPs.
func (f *Forwarder) cacheResolved(domain string, resp *dns.Msg) {
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		return
	}
	var ips []string
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			ips = append(ips, a.Addr.String())
		}
	}
	f.cache.Remember(domain, ips)
}

// trackMatched adds the A records of a shunt-matched domain to the ipset
// (through the tracker) before the client sees the answer.
//
// The match is re-checked when the rules changed while the IPs were being
// tracked: a mutation that removed the rule may have swept the tracker
// before Track ran, and the IPs would otherwise stay in the ipset with no
// rule explaining them.
func (f *Forwarder) trackMatched(ctx context.Context, domain string, resp *dns.Msg) {
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		return
	}
	matched, rules := f.matcher.matchRules(domain)
	if !matched {
		return
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			f.tracker.Track(ctx, domain, a.Addr.String())
		}
	}
	if f.matcher.changedSince(rules) && !f.matcher.Match(domain) {
		f.tracker.RemoveDomain(ctx, domain)
	}
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
