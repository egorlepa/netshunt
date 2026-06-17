package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/egorlepa/netshunt/internal/healthcheck"
	"github.com/egorlepa/netshunt/internal/shunt"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

func (s *Server) handleDiagnosticsPage(w http.ResponseWriter, r *http.Request) {
	s.render(r, w, templates.DiagnosticsPage())
}

func (s *Server) handleDiagnosticsLogs(w http.ResponseWriter, r *http.Request) {
	s.render(r, w, templates.DiagnosticsLogs(s.Logs.Entries()))
}

func (s *Server) handleDiagnosticsRun(w http.ResponseWriter, r *http.Request) {
	checks := healthcheck.Checks(s.Config, s.Shunts)
	names := make([]string, len(checks))
	for i, c := range checks {
		names[i] = c.Name
	}
	s.render(r, w, templates.DiagnosticsCheckList(names))
}

func (s *Server) handleDiagnosticsRunOne(w http.ResponseWriter, r *http.Request) {
	checks := healthcheck.Checks(s.Config, s.Shunts)
	i, err := strconv.Atoi(r.PathValue("i"))
	if err != nil || i < 0 || i >= len(checks) {
		errorResponse(w, "unknown check", http.StatusNotFound)
		return
	}
	result := checks[i].Run(r.Context())
	s.render(r, w, templates.DiagnosticsCheckResult(i, result))
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
