package web

import (
	"context"
	"net/http"

	"github.com/guras256/keenetic-split-tunnel/internal/netfilter"
	"github.com/guras256/keenetic-split-tunnel/internal/routing"
	"github.com/guras256/keenetic-split-tunnel/internal/service"
	"github.com/guras256/keenetic-split-tunnel/internal/web/templates"
)

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	services := []templates.ServiceStatus{
		svcStatus(ctx, service.Dnsmasq),
		svcStatus(ctx, service.DNSCrypt),
	}

	ipset := netfilter.NewIPSet(s.Config.IPSet.TableName)
	ipsetCount, _ := ipset.Count(ctx)

	groups, _ := s.Groups.List()
	entryCount := 0
	for _, g := range groups {
		if g.Enabled {
			entryCount += len(g.Entries)
		}
	}

	mode := routing.New(s.Config, s.Logger)
	routingActive, _ := mode.IsActive(ctx)

	data := templates.DashboardData{
		Services:      services,
		IPSetCount:    ipsetCount,
		GroupCount:    len(groups),
		EntryCount:    entryCount,
		RoutingMode:   s.Config.Routing.Mode,
		RoutingActive: routingActive,
	}

	templates.Dashboard(data).Render(ctx, w)
}

func svcStatus(ctx context.Context, svc service.Service) templates.ServiceStatus {
	st := templates.ServiceStatus{Name: svc.Name, Installed: svc.IsInstalled()}
	if st.Installed {
		st.Running = svc.IsRunning(ctx)
	}
	return st
}
