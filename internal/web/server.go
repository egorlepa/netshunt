package web

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/shunt"
)

//go:generate templ generate

//go:embed static/*
var staticFS embed.FS

// Reconciler is the interface the web server uses to trigger state reconciliation.
type Reconciler interface {
	Reconcile(ctx context.Context) error
	ApplyMutation(ctx context.Context) error
}

// Server is the web UI HTTP server.
type Server struct {
	Config     *config.Config
	Shunts     *shunt.Store
	Reconciler Reconciler
	Logger     *slog.Logger
	Version    string
	mux        *http.ServeMux
	ready      bool
}

// MarkReady signals that the daemon has finished initial setup.
func (s *Server) MarkReady() {
	s.ready = true
}

// NewServer creates a web server with all routes registered.
func NewServer(cfg *config.Config, shunts *shunt.Store, reconciler Reconciler, logger *slog.Logger, version string) *Server {
	s := &Server{
		Config:     cfg,
		Shunts:     shunts,
		Reconciler: reconciler,
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

	// Settings.
	s.mux.HandleFunc("PUT /settings", s.handleUpdateSettings)

	// Actions.
	s.mux.HandleFunc("POST /actions/reconcile", s.handleActionReconcile)
	s.mux.HandleFunc("POST /actions/restart", s.handleActionRestart)

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

// triggerMutation applies shunt changes in the background after a store mutation.
func (s *Server) triggerMutation() {
	go func() {
		if err := s.Reconciler.ApplyMutation(context.Background()); err != nil {
			s.Logger.Error("apply mutation failed", "error", err)
		}
	}()
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
