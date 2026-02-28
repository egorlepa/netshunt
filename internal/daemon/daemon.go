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
	Reconciler *Reconciler
	Forwarder  *dns.Forwarder
	Logger     *slog.Logger
	LogBuf     *platform.LogBuffer
	Version    string
}

// New creates a new Daemon with the DNS forwarder and reconciler wired up.
func New(cfg *config.Config, shunts *shunt.Store, logger *slog.Logger, logBuf *platform.LogBuffer, version string) *Daemon {
	ipset4 := netfilter.NewIPSet(cfg.IPSet.TableName)
	var ipset6 *netfilter.IPSet
	if cfg.IPv6 {
		ipset6 = netfilter.NewIPSet6(cfg.IPSet.TableName + "6")
	}
	tracker := dns.NewTracker(ipset4, ipset6, logger)
	upstream := fmt.Sprintf("127.0.0.1:%d", cfg.DNSCrypt.Port)
	forwarder := dns.NewForwarder(cfg.DNS.ListenAddr, upstream, cfg.IPv6, tracker, logger)

	return &Daemon{
		Config:     cfg,
		Shunts:     shunts,
		Reconciler: NewReconciler(cfg, shunts, forwarder, logger),
		Forwarder:  forwarder,
		Logger:     logger,
		LogBuf:     logBuf,
		Version:    version,
	}
}

// Run starts the daemon, blocking until a signal is received.
func (d *Daemon) Run(ctx context.Context) error {
	// Write PID file.
	if err := os.WriteFile(platform.PidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
		d.Logger.Warn("failed to write pid file", "error", err)
	}
	defer os.Remove(platform.PidFile)

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
	webServer := web.NewServer(d.Config, d.Shunts, d.Reconciler, d.Forwarder.TrackerRef(), d.LogBuf, d.Logger, d.Version)
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
	d.Logger.Info("daemon started")

	<-ctx.Done()
	d.Logger.Info("shutting down")

	d.Forwarder.Stop()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	httpServer.Shutdown(shutdownCtx)
	return nil
}
