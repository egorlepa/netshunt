package web

import (
	"context"
	"os"
	"time"

	"github.com/egorlepa/netshunt/internal/dns"
	"github.com/egorlepa/netshunt/internal/metrics"
)

// Update jobs, the label of the update metrics.
const (
	jobBlocklist = "blocklist"
	jobGeosite   = "geosite"
)

// scrapeTimeout bounds the only collector input that may exec (the cached
// kill switch counter).
const scrapeTimeout = 5 * time.Second

// Metrics returns the registry served on GET /metrics; the daemon adds its
// own collectors to it.
func (s *Server) Metrics() *metrics.Registry { return s.metrics }

// StartBackgroundHealth starts the once-a-minute healthcheck run (without
// the proxy connectivity checks) that feeds netshunt_healthcheck_ok and the
// dashboard's base checks. It stops with ctx.
func (s *Server) StartBackgroundHealth(ctx context.Context) {
	go s.health.Loop(ctx)
}

// registerMetrics adds the web server's collectors: DNS, routing state,
// updates, healthcheck and process.
func (s *Server) registerMetrics() {
	s.metrics.Register(metrics.ProcessCollector(s.Version))
	s.metrics.Register(s.collectDNS)
	s.metrics.Register(s.collectRouting)
	s.metrics.Register(s.collectUpdates)
	s.metrics.Register(s.collectHealth)
}

func (s *Server) collectDNS(e *metrics.Emitter) {
	const (
		qHelp   = "DNS queries by how the forwarder answered them."
		durHelp = "Time from receiving a query to having the upstream answer or giving up (upstream path only)."
		reqHelp = "DoH requests sent to the upstream (label: SNI)."
		winHelp = "Fan-out queries this upstream answered first."
		errHelp = "Failed DoH requests to the upstream (cancelled losers are not errors)."
	)
	e.Declare("netshunt_dns_queries_total", qHelp, metrics.TypeCounter)
	e.Declare("netshunt_dns_upstream_duration_seconds", durHelp, metrics.TypeHistogram)
	e.Declare("netshunt_dns_upstream_requests_total", reqHelp, metrics.TypeCounter)
	e.Declare("netshunt_dns_upstream_wins_total", winHelp, metrics.TypeCounter)
	e.Declare("netshunt_dns_upstream_errors_total", errHelp, metrics.TypeCounter)
	if s.Forwarder == nil {
		return
	}
	for _, r := range dns.QueryResults() {
		e.Counter("netshunt_dns_queries_total", qHelp, float64(s.Forwarder.QueryCount(r)), metrics.L("result", r.String())...)
	}
	e.Histogram("netshunt_dns_upstream_duration_seconds", durHelp, s.Forwarder.UpstreamDuration())

	// UpstreamStats reads the current client list through its atomic
	// pointer, so a concurrent SetUpstreams is safe; counters of replaced
	// clients disappear (a counter reset for Prometheus). Two upstreams with
	// the same SNI are summed so the label set stays unique.
	type agg struct{ q, w, e uint64 }
	var order []string
	by := map[string]*agg{}
	for _, st := range s.Forwarder.UpstreamStats() {
		a := by[st.Upstream.SNI]
		if a == nil {
			a = &agg{}
			by[st.Upstream.SNI] = a
			order = append(order, st.Upstream.SNI)
		}
		a.q += st.Queries
		a.w += st.Wins
		a.e += st.Errors
	}
	for _, sni := range order {
		a := by[sni]
		l := metrics.L("upstream", sni)
		e.Counter("netshunt_dns_upstream_requests_total", reqHelp, float64(a.q), l...)
		e.Counter("netshunt_dns_upstream_wins_total", winHelp, float64(a.w), l...)
		e.Counter("netshunt_dns_upstream_errors_total", errHelp, float64(a.e), l...)
	}
}

func (s *Server) collectRouting(e *metrics.Emitter) {
	var members, domains, enabled, entries int
	if s.Tracker != nil {
		members = s.Tracker.Members()
		domains, _ = s.Tracker.Count()
	}
	if s.Shunts != nil {
		_, enabled, entries, _ = s.Shunts.Counts()
	}
	e.Gauge("netshunt_ipset_members", "Members of the kernel ipset (DNS-tracked IPs plus static entries), as the tracker knows them.", float64(members))
	e.Gauge("netshunt_tracked_domains", "Domains whose resolved IPs are tracked in the ipset.", float64(domains))
	e.Gauge("netshunt_shunts_enabled", "Enabled shunts.", float64(enabled))
	e.Gauge("netshunt_shunt_entries", "Entries of the enabled shunts (geosite shunts expanded).", float64(entries))

	ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
	defer cancel()
	e.Counter("netshunt_killswitch_drops_total", "Packets the kill switch chain dropped: shunted addresses that tried to leave directly (read at most every 10 s).",
		float64(s.ksDrops.get(ctx)))
}

func (s *Server) collectUpdates(e *metrics.Emitter) {
	const (
		tsHelp   = "Unix time of the last successful update (blocklist: newest fetch of an enabled source, persisted; geosite: dlc.dat mtime); 0 when none."
		failHelp = "Failed scheduled or UI-triggered updates since start (blocklist: per source, a rejected empty or shrunk list included)."
	)
	var bl time.Time
	if s.Blocklist != nil {
		for _, st := range s.Blocklist.States() {
			if st.Enabled && st.LastFetched.After(bl) {
				bl = st.LastFetched
			}
		}
	}
	var gs time.Time
	if fi, err := os.Stat(s.geositeFile); err == nil {
		gs = fi.ModTime()
	}
	for _, j := range []struct {
		job string
		at  time.Time
	}{{jobBlocklist, bl}, {jobGeosite, gs}} {
		v := 0.0
		if !j.at.IsZero() {
			v = float64(j.at.UnixNano()) / 1e9
		}
		e.Gauge("netshunt_update_last_success_timestamp_seconds", tsHelp, v, metrics.L("job", j.job)...)
	}
	e.Counter("netshunt_update_failures_total", failHelp, float64(s.blocklistFailures.Load()), metrics.L("job", jobBlocklist)...)
	e.Counter("netshunt_update_failures_total", failHelp, float64(s.geositeFailures.Load()), metrics.L("job", jobGeosite)...)
}

func (s *Server) collectHealth(e *metrics.Emitter) {
	const help = "Result of the last background healthcheck per check (1 ok, 0 failed or warning); proxy connectivity checks are not run in the background."
	e.Declare("netshunt_healthcheck_ok", help, metrics.TypeGauge)
	res, _ := s.health.LastBase()
	for _, r := range res {
		v := 0.0
		if r.Passed && !r.Warn {
			v = 1
		}
		e.Gauge("netshunt_healthcheck_ok", help, v, metrics.L("check", r.Name)...)
	}
}
