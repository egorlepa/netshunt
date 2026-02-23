package web

import (
	"context"
	"net/http"

	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/routing"
	"github.com/egorlepa/netshunt/internal/service"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

func (s *Server) dashboardData(ctx context.Context) templates.DashboardData {
	services := []templates.ServiceStatus{
		svcStatus(ctx, service.Dnsmasq),
		svcStatus(ctx, service.DNSCrypt),
	}

	ipset := netfilter.NewIPSet(s.Config.IPSet.TableName)
	ipsetCount, _ := ipset.Count(ctx)

	shunts, _ := s.Shunts.List()
	entryCount := 0
	for _, sh := range shunts {
		if sh.Enabled {
			entryCount += len(sh.Entries)
		}
	}

	mode := routing.New(s.Config, s.Logger)
	routingActive, _ := mode.IsActive(ctx)

	return templates.DashboardData{
		Services:      services,
		IPSetCount:    ipsetCount,
		ShuntCount:    len(shunts),
		EntryCount:    entryCount,
		RoutingMode:   "redirect",
		RoutingActive: routingActive,
		Version:       s.Version,
	}
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data := s.dashboardData(ctx)
	templates.Dashboard(data).Render(ctx, w)
}

func (s *Server) handleDashboardContent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data := s.dashboardData(ctx)
	templates.DashboardContent(data).Render(ctx, w)
}

func svcStatus(ctx context.Context, svc service.Service) templates.ServiceStatus {
	st := templates.ServiceStatus{Name: svc.Name, Installed: svc.IsInstalled()}
	if st.Installed {
		st.Running = svc.IsRunning(ctx)
	}
	return st
}
