package web

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/a-h/templ"

	"github.com/egorlepa/netshunt/internal/blocklist"
	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/dns"
	"github.com/egorlepa/netshunt/internal/platform"
	"github.com/egorlepa/netshunt/internal/shunt"
)

//go:generate templ generate

//go:embed static/*
var staticFS embed.FS

// Reconciler is the interface the web server uses to trigger state reconciliation.
type Reconciler interface {
	Reconcile(ctx context.Context) error
	ApplyMutation(ctx context.Context) error
	ApplyBlocklist(ctx context.Context) error
	SwitchProxy(ctx context.Context) error
}

// Scheduler is the optional interface the web server uses to apply auto-update
// schedule changes live (without daemon restart). May be nil if not wired up.
type Scheduler interface {
	Reconfigure() error
}

// TrackerStats is the interface the web server uses to read DNS tracker state.
type TrackerStats interface {
	Count() (domains int, ips int)
}

// LogReader is the interface the web server uses to read recent log entries.
type LogReader interface {
	Entries() []platform.LogEntry
}

// Server is the web UI HTTP server.
type Server struct {
	Config     *config.Config
	Shunts     *shunt.Store
	Blocklist  *blocklist.Store
	Forwarder  *dns.Forwarder
	Reconciler Reconciler
	Scheduler  Scheduler
	Tracker    TrackerStats
	Logs       LogReader
	Logger     *slog.Logger
	Version    string
	mux        *http.ServeMux
	ready      bool
}

// SetScheduler attaches a Scheduler after construction (the scheduler is
// built later in the daemon lifecycle than the web server).
func (s *Server) SetScheduler(sch Scheduler) {
	s.Scheduler = sch
}

// MarkReady signals that the daemon has finished initial setup.
func (s *Server) MarkReady() {
	s.ready = true
}

// NewServer creates a web server with all routes registered.
func NewServer(cfg *config.Config, shunts *shunt.Store, blocklistStore *blocklist.Store, forwarder *dns.Forwarder, reconciler Reconciler, tracker TrackerStats, logs LogReader, logger *slog.Logger, version string) *Server {
	s := &Server{
		Config:     cfg,
		Shunts:     shunts,
		Blocklist:  blocklistStore,
		Forwarder:  forwarder,
		Reconciler: reconciler,
		Tracker:    tracker,
		Logs:       logs,
		Logger:     logger,
		Version:    version,
		mux:        http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	// Static files.
	staticSub, _ := fs.Sub(staticFS, "static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Pages.
	s.mux.HandleFunc("GET /{$}", s.handleDashboard)
	s.mux.HandleFunc("GET /dashboard-content", s.handleDashboardContent)
	s.mux.HandleFunc("GET /shunts", s.handleShuntsPage)
	s.mux.HandleFunc("GET /shunts/{name}", s.handleShuntDetail)
	s.mux.HandleFunc("GET /settings", s.handleSettingsPage)
	s.mux.HandleFunc("GET /diagnostics", s.handleDiagnosticsPage)
	s.mux.HandleFunc("GET /diagnostics/run", s.handleDiagnosticsRun)
	s.mux.HandleFunc("POST /diagnostics/probe", s.handleDiagnosticsProbe)
	s.mux.HandleFunc("GET /diagnostics/logs", s.handleDiagnosticsLogs)

	// Shunt mutations (htmx).
	s.mux.HandleFunc("POST /shunts", s.handleCreateShunt)
	s.mux.HandleFunc("DELETE /shunts/{name}", s.handleDeleteShunt)
	s.mux.HandleFunc("PUT /shunts/{name}/enable", s.handleEnableShunt)
	s.mux.HandleFunc("PUT /shunts/{name}/disable", s.handleDisableShunt)
	s.mux.HandleFunc("POST /shunts/{name}/entries", s.handleAddEntry)
	s.mux.HandleFunc("DELETE /shunts/{name}/entries/{value...}", s.handleDeleteEntry)
	s.mux.HandleFunc("POST /shunts/{name}/entries/bulk", s.handleBulkAddEntries)
	s.mux.HandleFunc("POST /shunts/import", s.handleImportShunts)
	s.mux.HandleFunc("GET /shunts/export", s.handleExportShunts)

	// Geosite.
	s.mux.HandleFunc("GET /geosite", s.handleGeositePage)
	s.mux.HandleFunc("POST /geosite/download", s.handleGeositeDownload)
	s.mux.HandleFunc("POST /geosite/update", s.handleGeositeUpdate)
	s.mux.HandleFunc("PUT /geosite/auto-update", s.handleGeositeAutoUpdate)
	s.mux.HandleFunc("POST /geosite/import/{category}", s.handleGeositeImport)
	s.mux.HandleFunc("DELETE /geosite/import/{category}", s.handleGeositeRemove)

	// Blocklist.
	s.mux.HandleFunc("GET /blocklist", s.handleBlocklistPage)
	s.mux.HandleFunc("PUT /blocklist/enabled", s.handleBlocklistToggleEnabled)
	s.mux.HandleFunc("PUT /blocklist/response", s.handleBlocklistResponse)
	s.mux.HandleFunc("PUT /blocklist/sources/{id}/enabled", s.handleBlocklistSourceToggle)
	s.mux.HandleFunc("POST /blocklist/sources/{id}/update", s.handleBlocklistSourceUpdate)
	s.mux.HandleFunc("POST /blocklist/update", s.handleBlocklistUpdateAll)
	s.mux.HandleFunc("PUT /blocklist/auto-update", s.handleBlocklistAutoUpdate)

	// Settings.
	s.mux.HandleFunc("PUT /settings", s.handleUpdateSettings)

	// Actions.
	s.mux.HandleFunc("POST /actions/reconcile", s.handleActionReconcile)
	s.mux.HandleFunc("POST /actions/restart", s.handleActionRestart)
	s.mux.HandleFunc("POST /actions/switch-proxy", s.handleSwitchProxy)

	// Readiness probe.
	s.mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		if !s.ready {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// triggerMutation applies shunt changes after a store mutation.
func (s *Server) triggerMutation(ctx context.Context) {
	if err := s.Reconciler.ApplyMutation(ctx); err != nil {
		s.Logger.Error("apply mutation failed", "error", err)
	}
}

// toastTrigger sets HX-Trigger header to show a toast notification.
func toastTrigger(w http.ResponseWriter, msg, typ string) {
	data, _ := json.Marshal(map[string]any{
		"showToast": map[string]string{"message": msg, "type": typ},
	})
	w.Header().Set("HX-Trigger", string(data))
}

// errorResponse writes an HTMX-friendly error that shows as a toast instead of
// replacing the target element.
func errorResponse(w http.ResponseWriter, msg string, code int) {
	data, _ := json.Marshal(map[string]any{
		"showToast": map[string]string{"message": msg, "type": "error"},
	})
	w.Header().Set("HX-Retarget", "none")
	w.Header().Set("HX-Trigger", string(data))
	w.WriteHeader(code)
}

// render writes a templ component to w, logging any failure.
func (s *Server) render(r *http.Request, w http.ResponseWriter, c templ.Component) {
	if err := c.Render(r.Context(), w); err != nil {
		s.Logger.Warn("template render failed", "error", err)
	}
}
