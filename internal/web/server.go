package web

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/group"
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
	Groups     *group.Store
	Reconciler Reconciler
	Logger     *slog.Logger
	Version    string
	mux        *http.ServeMux
}

// NewServer creates a web server with all routes registered.
func NewServer(cfg *config.Config, groups *group.Store, reconciler Reconciler, logger *slog.Logger, version string) *Server {
	s := &Server{
		Config:     cfg,
		Groups:     groups,
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
	s.mux.HandleFunc("GET /groups", s.handleGroupsPage)
	s.mux.HandleFunc("GET /groups/{name}", s.handleGroupDetail)
	s.mux.HandleFunc("GET /settings", s.handleSettingsPage)
	s.mux.HandleFunc("GET /diagnostics", s.handleDiagnosticsPage)
	s.mux.HandleFunc("GET /diagnostics/run", s.handleDiagnosticsRun)
	s.mux.HandleFunc("POST /diagnostics/probe", s.handleDiagnosticsProbe)

	// Group mutations (htmx).
	s.mux.HandleFunc("POST /groups", s.handleCreateGroup)
	s.mux.HandleFunc("DELETE /groups/{name}", s.handleDeleteGroup)
	s.mux.HandleFunc("PUT /groups/{name}/enable", s.handleEnableGroup)
	s.mux.HandleFunc("PUT /groups/{name}/disable", s.handleDisableGroup)
	s.mux.HandleFunc("POST /groups/{name}/entries", s.handleAddEntry)
	s.mux.HandleFunc("DELETE /groups/{name}/entries/{value...}", s.handleDeleteEntry)
	s.mux.HandleFunc("POST /groups/{name}/entries/bulk", s.handleBulkAddEntries)
	s.mux.HandleFunc("POST /groups/import", s.handleImportGroups)
	s.mux.HandleFunc("GET /groups/export", s.handleExportGroups)

	// Settings.
	s.mux.HandleFunc("PUT /settings", s.handleUpdateSettings)

	// Actions.
	s.mux.HandleFunc("POST /actions/reconcile", s.handleActionReconcile)
	s.mux.HandleFunc("POST /actions/restart", s.handleActionRestart)
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// triggerMutation applies group changes in the background after a store mutation.
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
