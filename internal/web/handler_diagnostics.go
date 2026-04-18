package web

import (
	"net/http"
	"strings"

	"github.com/egorlepa/netshunt/internal/shunt"
	"github.com/egorlepa/netshunt/internal/healthcheck"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

func (s *Server) handleDiagnosticsPage(w http.ResponseWriter, r *http.Request) {
	s.render(r, w, templates.DiagnosticsPage())
}

func (s *Server) handleDiagnosticsLogs(w http.ResponseWriter, r *http.Request) {
	s.render(r, w, templates.DiagnosticsLogs(s.Logs.Entries()))
}

func (s *Server) handleDiagnosticsRun(w http.ResponseWriter, r *http.Request) {
	results := healthcheck.RunChecks(r.Context(), s.Config, s.Shunts)
	s.render(r, w, templates.DiagnosticsResults(results))
}

func (s *Server) handleDiagnosticsProbe(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	domain := strings.TrimSpace(r.FormValue("domain"))
	if domain == "" {
		errorResponse(w, "domain is required", http.StatusBadRequest)
		return
	}

	// Ensure the domain is in a shunt so it resolves through the pipeline.
	// Run mutation so the forwarder matcher is updated before we probe.
	_ = s.Shunts.EnsureDefaultShunt()
	if err := s.Shunts.AddEntry(shunt.DefaultShuntName, domain); err == nil {
		_ = s.Reconciler.ApplyMutation(r.Context())
	}

	probe, err := healthcheck.ProbeDomain(r.Context(), s.Config, domain)
	if err != nil {
		s.render(r, w, templates.DiagnosticsProbeError(domain, err.Error()))
		return
	}
	s.render(r, w, templates.DiagnosticsProbeResult(*probe))
}
