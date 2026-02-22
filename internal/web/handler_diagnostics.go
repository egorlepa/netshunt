package web

import (
	"net/http"
	"strings"

	"github.com/egorlepa/netshunt/internal/group"
	"github.com/egorlepa/netshunt/internal/healthcheck"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

func (s *Server) handleDiagnosticsPage(w http.ResponseWriter, r *http.Request) {
	templates.DiagnosticsPage().Render(r.Context(), w)
}

func (s *Server) handleDiagnosticsRun(w http.ResponseWriter, r *http.Request) {
	results := healthcheck.RunChecks(r.Context(), s.Config, s.Groups)
	templates.DiagnosticsResults(results).Render(r.Context(), w)
}

func (s *Server) handleDiagnosticsProbe(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	domain := strings.TrimSpace(r.FormValue("domain"))
	if domain == "" {
		errorResponse(w, "domain is required", http.StatusBadRequest)
		return
	}

	// Ensure the domain is in a group so it resolves through the pipeline.
	// Run reconcile synchronously so dnsmasq has the config before we probe.
	_ = s.Groups.EnsureDefaultGroup()
	if err := s.Groups.AddEntry(group.DefaultGroupName, domain); err == nil {
		_ = s.Reconciler.ApplyMutation(r.Context())
	}

	probe, err := healthcheck.ProbeDomain(r.Context(), s.Config, domain)
	if err != nil {
		templates.DiagnosticsProbeError(domain, err.Error()).Render(r.Context(), w)
		return
	}
	templates.DiagnosticsProbeResult(*probe).Render(r.Context(), w)
}
