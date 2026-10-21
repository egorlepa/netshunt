package web

import (
	"context"
	"net/http"
	"time"

	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

func (s *Server) dashboardData(ctx context.Context) templates.DashboardData {
	cfg := s.Config.Load()
	ipset := netfilter.NewIPSet(cfg.IPSet.TableName)
	ipsetCount, _ := ipset.Count(ctx)

	shunts, _ := s.Shunts.List()
	enabledCount, entryCount := 0, 0
	for _, sh := range shunts {
		if sh.Enabled {
			enabledCount++
			entryCount += len(sh.Entries)
		}
	}

	trackedDomains, trackedIPs := s.Tracker.Count()

	var blocklistProblems []string
	if cfg.Blocklist.Enabled {
		now := time.Now()
		for _, sv := range s.blocklistSourceViews() {
			if p := sv.State.Problem(now); p != "" {
				blocklistProblems = append(blocklistProblems, sv.Preset.Name+": "+p)
			}
		}
	}

	return templates.DashboardData{
		IPSetCount:        ipsetCount,
		ShuntCount:        len(shunts),
		EnabledShuntCount: enabledCount,
		EntryCount:        entryCount,
		TrackedDomains:    trackedDomains,
		TrackedIPs:        trackedIPs,
		BlocklistProblems: blocklistProblems,
		Routing:           cfg.Routing,
		Version:           s.Version,
	}
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	data := s.dashboardData(r.Context())
	s.render(r, w, templates.Dashboard(data))
}

func (s *Server) handleDashboardContent(w http.ResponseWriter, r *http.Request) {
	data := s.dashboardData(r.Context())
	s.render(r, w, templates.DashboardContent(data))
}
