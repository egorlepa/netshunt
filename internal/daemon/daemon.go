package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/group"
	"github.com/guras256/keenetic-split-tunnel/internal/platform"
	"github.com/guras256/keenetic-split-tunnel/internal/web"
)

// Daemon runs the long-lived process: web UI server + periodic ipset refresh.
type Daemon struct {
	Config     *config.Config
	Groups     *group.Store
	Reconciler *Reconciler
	Logger     *slog.Logger
}

// New creates a new Daemon.
func New(cfg *config.Config, groups *group.Store, logger *slog.Logger) *Daemon {
	return &Daemon{
		Config:     cfg,
		Groups:     groups,
		Reconciler: NewReconciler(cfg, groups, logger),
		Logger:     logger,
	}
}

// Run starts the daemon, blocking until a signal is received.
func (d *Daemon) Run(ctx context.Context) error {
	// Write PID file.
	if err := os.WriteFile(platform.PidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
		d.Logger.Warn("failed to write pid file", "error", err)
	}
	defer os.Remove(platform.PidFile)

	// Initial reconcile.
	if err := d.Reconciler.Reconcile(ctx); err != nil {
		d.Logger.Error("initial reconcile failed", "error", err)
	}

	// Setup signal handling.
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start web server.
	webServer := web.NewServer(d.Config, d.Groups, d.Reconciler, d.Logger)
	httpServer := &http.Server{
		Addr:    d.Config.Daemon.WebListen,
		Handler: webServer,
	}

	go func() {
		d.Logger.Info("web UI started", "listen", d.Config.Daemon.WebListen)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			d.Logger.Error("web server error", "error", err)
		}
	}()

	// Start periodic ipset refresh.
	interval := d.Config.Daemon.ResolveIntervalDuration()
	d.Logger.Info("starting periodic ipset refresh", "interval", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	d.Logger.Info("daemon started")

	for {
		select {
		case <-ctx.Done():
			d.Logger.Info("shutting down")
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			httpServer.Shutdown(shutdownCtx)
			return nil
		case <-ticker.C:
			if err := d.Reconciler.RefreshIPSet(ctx); err != nil {
				d.Logger.Error("periodic refresh failed", "error", err)
			}
		}
	}
}
