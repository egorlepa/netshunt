package web

import (
	"context"
	"net/http"

	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

func (s *Server) dashboardData(ctx context.Context) templates.DashboardData {
	ipset := netfilter.NewIPSet(s.Config.IPSet.TableName)
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

	return templates.DashboardData{
		IPSetCount:        ipsetCount,
		ShuntCount:        len(shunts),
		EnabledShuntCount: enabledCount,
		EntryCount:        entryCount,
		TrackedDomains:    trackedDomains,
		TrackedIPs:        trackedIPs,
		Routing:           s.Config.Routing,
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
