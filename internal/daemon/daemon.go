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

	"github.com/egorlepa/netshunt/internal/blocklist"
	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/dns"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/platform"
	"github.com/egorlepa/netshunt/internal/shunt"
	"github.com/egorlepa/netshunt/internal/web"
)

// Daemon is the long-lived process that runs the DNS forwarder, reconciles
// routing state, and serves the web UI.
type Daemon struct {
	Config     *config.Config
	Shunts     *shunt.Store
	Blocklist  *blocklist.Store
	Reconciler *Reconciler
	Forwarder  *dns.Forwarder
	Logger     *slog.Logger
	LogBuf     *platform.LogBuffer
	Version    string
}

// New creates a new Daemon with the DNS forwarder and reconciler wired up.
func New(cfg *config.Config, shunts *shunt.Store, logger *slog.Logger, logBuf *platform.LogBuffer, version string) (*Daemon, error) {
	tracker := dns.NewTracker(netfilter.NewIPSet(cfg.IPSet.TableName), logger)
	upstream := fmt.Sprintf("127.0.0.1:%d", cfg.DNSCrypt.Port)
	forwarder := dns.NewForwarder(cfg.DNS.ListenAddr, upstream, tracker, logger)

	blocklistStore, err := blocklist.NewStore(platform.BlocklistFile, platform.BlocklistDir)
	if err != nil {
		return nil, fmt.Errorf("init blocklist store: %w", err)
	}

	return &Daemon{
		Config:     cfg,
		Shunts:     shunts,
		Blocklist:  blocklistStore,
		Reconciler: NewReconciler(cfg, shunts, forwarder, blocklistStore, logger),
		Forwarder:  forwarder,
		Logger:     logger,
		LogBuf:     logBuf,
		Version:    version,
	}, nil
}

// Run starts the daemon, blocking until a signal is received.
func (d *Daemon) Run(ctx context.Context) error {
	// Write PID file.
	if err := os.WriteFile(platform.PidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
		d.Logger.Warn("failed to write pid file", "error", err)
	}
	defer func() { _ = os.Remove(platform.PidFile) }()

	// Setup signal handling.
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// 1. Initial reconcile — populates matcher + ipset before DNS starts.
	if err := d.Reconciler.Reconcile(ctx); err != nil {
		d.Logger.Error("initial reconcile failed", "error", err)
	}

	// 2. Start DNS forwarder (now has domain list ready).
	if err := d.Forwarder.Start(); err != nil {
		return fmt.Errorf("start dns forwarder: %w", err)
	}

	// 4. Start web server.
	webServer := web.NewServer(d.Config, d.Shunts, d.Blocklist, d.Forwarder, d.Reconciler, d.Forwarder.TrackerRef(), d.LogBuf, d.Logger, d.Version)
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

	webServer.MarkReady()

	// 5. Start auto-update scheduler (blocklist + geosite). Web server gets
	// a handle so settings changes can live-reconfigure without restart.
	scheduler := NewScheduler(d.Config, webServer, d.Logger)
	webServer.SetScheduler(scheduler)
	if err := scheduler.Start(); err != nil {
		d.Logger.Warn("scheduler start failed", "error", err)
	}

	d.Logger.Info("daemon started")

	<-ctx.Done()
	d.Logger.Info("shutting down")

	scheduler.Stop()
	d.Forwarder.Stop()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		d.Logger.Warn("http server shutdown", "error", err)
	}
	return nil
}
