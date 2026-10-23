package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/egorlepa/netshunt/internal/dns"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/routing"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

// feedRows is how many matched answers the dashboard keeps on screen.
const feedRows = 60

// Bars on the dashboard: the busiest shunts and clients of the last hour.
const (
	topShunts  = 8
	topClients = 6
)

// ksDropsTTL bounds how often the dashboard poll execs iptables for the
// kill switch counter.
const ksDropsTTL = 10 * time.Second

// ksCounter caches the kill switch DROP counter.
type ksCounter struct {
	read func(ctx context.Context) (uint64, error)
	mu   sync.Mutex
	at   time.Time
	n    uint64
}

func (k *ksCounter) get(ctx context.Context) uint64 {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.at.IsZero() && time.Since(k.at) < ksDropsTTL {
		return k.n
	}
	if n, err := k.read(ctx); err == nil {
		k.n = n
	}
	k.at = time.Now()
	return k.n
}

func readKillSwitchDrops(ctx context.Context) (uint64, error) {
	return netfilter.NewIPTables().DropPackets(ctx, "filter", routing.KillSwitchChain)
}

// dashboardStats is the strip of the dashboard.
func (s *Server) dashboardStats(ctx context.Context) templates.DashboardStats {
	var st templates.DashboardStats
	if s.Tracker != nil {
		st.IPs = s.Tracker.Members()
		st.Domains, _ = s.Tracker.Count()
	}
	if s.Shunts != nil {
		_, st.Shunts, st.Entries, _ = s.Shunts.Counts()
	}
	st.KSDrops = s.ksDrops.get(ctx)
	return st
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	s.render(r, w, templates.Dashboard(s.dashboardStats(r.Context())))
}

// handleDashboardHealth answers the hero: the shared healthcheck run.
func (s *Server) handleDashboardHealth(w http.ResponseWriter, r *http.Request) {
	res, _, err := s.health.Results(r.Context())
	if err != nil {
		return // the client went away
	}
	s.render(r, w, templates.DashboardHealth(res))
}

// activityResponse is GET /api/activity: the matched answers newer than
// `since` (newest first, at most feedRows), the latest sequence number,
// how many the ring holds, the last hour per shunt and per client, and the
// strip numbers.
type activityResponse struct {
	Seq     uint64                   `json:"seq"`
	Held    int                      `json:"held"`
	Entries []dns.ActivityEntry      `json:"entries"`
	Shunts  []dns.ActivityCount      `json:"shunts"`
	Clients []dns.ActivityCount      `json:"clients"`
	Stats   templates.DashboardStats `json:"stats"`
}

func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	resp := activityResponse{Entries: []dns.ActivityEntry{}, Shunts: []dns.ActivityCount{}, Clients: []dns.ActivityCount{}}
	if s.Forwarder != nil {
		a := s.Forwarder.Activity()
		entries, seq, held := a.Since(since, feedRows)
		if since > seq {
			// The daemon restarted under the page: start over.
			entries, seq, held = a.Since(0, feedRows)
		}
		shunts, clients := a.LastHour()
		resp.Seq, resp.Held = seq, held
		if entries != nil {
			resp.Entries = entries
		}
		resp.Shunts = shunts[:min(len(shunts), topShunts)]
		resp.Clients = clients[:min(len(clients), topClients)]
	}
	resp.Stats = s.dashboardStats(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}
