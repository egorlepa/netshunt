package web

import (
	"context"
	"embed"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/group"
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
	mux        *http.ServeMux
}

// NewServer creates a web server with all routes registered.
func NewServer(cfg *config.Config, groups *group.Store, reconciler Reconciler, logger *slog.Logger) *Server {
	s := &Server{
		Config:     cfg,
		Groups:     groups,
		Reconciler: reconciler,
		Logger:     logger,
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
	s.mux.HandleFunc("GET /groups", s.handleGroupsPage)
	s.mux.HandleFunc("GET /groups/{name}", s.handleGroupDetail)
	s.mux.HandleFunc("GET /settings", s.handleSettingsPage)

	// Group mutations (htmx).
	s.mux.HandleFunc("POST /groups", s.handleCreateGroup)
	s.mux.HandleFunc("DELETE /groups/{name}", s.handleDeleteGroup)
	s.mux.HandleFunc("PUT /groups/{name}/enable", s.handleEnableGroup)
	s.mux.HandleFunc("PUT /groups/{name}/disable", s.handleDisableGroup)
	s.mux.HandleFunc("POST /groups/{name}/entries", s.handleAddEntry)
	s.mux.HandleFunc("DELETE /groups/{name}/entries/{value...}", s.handleDeleteEntry)
	s.mux.HandleFunc("POST /groups/import", s.handleImportGroups)

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
