package web

import (
	"net/http"
	"strconv"

	"github.com/egorlepa/netshunt/internal/healthcheck"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

func (s *Server) checkNames() []string {
	checks := healthcheck.Checks(s.Config.Load(), s.Shunts)
	names := make([]string, len(checks))
	for i, c := range checks {
		names[i] = c.Name
	}
	return names
}

func (s *Server) handleDiagnosticsPage(w http.ResponseWriter, r *http.Request) {
	s.render(r, w, templates.DiagnosticsPage(s.checkNames()))
}

func (s *Server) handleDiagnosticsLogs(w http.ResponseWriter, r *http.Request) {
	s.render(r, w, templates.DiagnosticsLogs(s.Logs.Entries()))
}

func (s *Server) handleDiagnosticsRun(w http.ResponseWriter, r *http.Request) {
	s.render(r, w, templates.DiagnosticsCheckList(s.checkNames()))
}

func (s *Server) handleDiagnosticsRunOne(w http.ResponseWriter, r *http.Request) {
	checks := healthcheck.Checks(s.Config.Load(), s.Shunts)
	i, err := strconv.Atoi(r.PathValue("i"))
	if err != nil || i < 0 || i >= len(checks) {
		errorResponse(w, "unknown check", http.StatusNotFound)
		return
	}
	result := checks[i].Execute(r.Context())
	s.render(r, w, templates.DiagnosticsCheckResult(i, result))
}
