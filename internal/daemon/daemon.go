package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/egorlepa/netshunt/internal/blocklist"
	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/dns"
	"github.com/egorlepa/netshunt/internal/geosite"
	"github.com/egorlepa/netshunt/internal/healthcheck"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/platform"
	"github.com/egorlepa/netshunt/internal/shunt"
	"github.com/egorlepa/netshunt/internal/web"
)

// trackerSaveInterval bounds how often the tracker state is written: at most
// once per interval while domains change, plus once at shutdown.
const trackerSaveInterval = 5 * time.Second

// Daemon is the long-lived process that runs the DNS forwarder, reconciles
// routing state, and serves the web UI.
type Daemon struct {
	Config     *config.Live
	Shunts     *shunt.Store
	Blocklist  *blocklist.Store
	Geosite    *geosite.Index
	Reconciler *Reconciler
	Forwarder  *dns.Forwarder
	Logger     *slog.Logger
	LogBuf     *platform.LogBuffer
	Version    string
}

// New creates a new Daemon with the DNS forwarder and reconciler wired up.
func New(cfg *config.Config, shunts *shunt.Store, logger *slog.Logger, logBuf *platform.LogBuffer, version string) (*Daemon, error) {
	// One netlink-backed ipset and conntrack for the process, shared by the
	// tracker (members, flows) and the reconciler (table creation).
	ipset := netfilter.NewIPSet(cfg.IPSet.TableName, netfilter.WithLogger(logger))
	conntrack := netfilter.NewConntrack(netfilter.WithLogger(logger))
	logger.Info("netfilter backends", "ipset", ipset.Backend(), "conntrack", conntrack.Backend())
	tracker := dns.NewTracker(ipset, logger)
	tracker.Conntrack = conntrack
	tracker.EnablePersistence(platform.TrackerFile, trackerSaveInterval)
	forwarder, err := dns.NewForwarder(cfg.DNS.ListenAddr, dns.ConfigUpstreams(cfg.DNS), tracker, logger)
	if err != nil {
		// A hand-edited config with a bad upstream must not leave the LAN
		// without DNS: fall back to the defaults.
		logger.Error("invalid dns upstreams, using defaults", "error", err)
		forwarder, err = dns.NewForwarder(cfg.DNS.ListenAddr, dns.ConfigUpstreams(config.DNSConfig{}), tracker, logger)
		if err != nil {
			return nil, fmt.Errorf("init dns forwarder: %w", err)
		}
	}

	blocklistStore, err := blocklist.NewStore(platform.BlocklistFile, platform.BlocklistDir)
	if err != nil {
		return nil, fmt.Errorf("init blocklist store: %w", err)
	}
	// Lists of presets that no longer exist and temp files of interrupted
	// downloads only take space on the stick.
	if removed, err := blocklistStore.CleanCache(); err != nil {
		logger.Warn("blocklist cache cleanup failed", "error", err, "removed", removed)
	} else if len(removed) > 0 {
		logger.Info("blocklist cache cleaned", "removed", removed)
	}

	// Geosite shunts are references: their entries are read from dlc.dat
	// through the index whenever the matcher is rebuilt.
	geositeIndex := geosite.NewIndex(platform.GeositeFile, logger)
	shunts.SetGeositeProvider(geositeIndex)

	live := config.NewLive(cfg)
	return &Daemon{
		Config:     live,
		Shunts:     shunts,
		Blocklist:  blocklistStore,
		Geosite:    geositeIndex,
		Reconciler: NewReconciler(live, shunts, forwarder, blocklistStore, ipset, logger),
		Forwarder:  forwarder,
		Logger:     logger,
		LogBuf:     logBuf,
		Version:    version,
	}, nil
}

// Run starts the daemon, blocking until a signal is received.
func (d *Daemon) Run(ctx context.Context) error {
	// Write PID file.
	pid := fmt.Sprintf("%d", os.Getpid())
	if err := os.WriteFile(platform.PidFile, []byte(pid), 0644); err != nil {
		d.Logger.Warn("failed to write pid file", "error", err)
	}
	// Remove it only while it is still ours: a daemon started after this one
	// has already written its own PID.
	defer func() {
		if data, err := os.ReadFile(platform.PidFile); err == nil && strings.TrimSpace(string(data)) == pid {
			_ = os.Remove(platform.PidFile)
		}
	}()

	// Setup signal handling.
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if n, err := healthcheck.RemoveStaleConnectivityRules(ctx); err != nil {
		d.Logger.Warn("failed to remove stale healthcheck rules", "error", err)
	} else if n > 0 {
		d.Logger.Info("removed stale healthcheck rules", "count", n)
	}

	d.normalizeShunts()

	// 1. Initial reconcile - populates matcher + ipset before DNS starts.
	if err := d.Reconciler.Reconcile(ctx); err != nil {
		d.Logger.Error("initial reconcile failed", "error", err)
	}

	// 2. Start DNS forwarder (now has domain list ready).
	if err := d.Forwarder.Start(); err != nil {
		return fmt.Errorf("start dns forwarder: %w", err)
	}

	// 4. Start web server.
	webServer := web.NewServer(d.Config, d.Shunts, d.Blocklist, d.Geosite, d.Forwarder, d.Reconciler, d.Forwarder.TrackerRef(), d.LogBuf, d.Logger, d.Version)
	httpServer := &http.Server{
		Addr:    d.Config.Load().Daemon.WebListen,
		Handler: webServer,
	}

	go func() {
		d.Logger.Info("web UI started", "listen", d.Config.Load().Daemon.WebListen)
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
	d.saveTracker()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		d.Logger.Warn("http server shutdown", "error", err)
	}
	return nil
}

// normalizeShunts drops, once, the geosite entries earlier versions copied
// into shunts.yaml: geosite shunts are references now. The only write to
// the shunts file at startup, and only when there is something to drop.
func (d *Daemon) normalizeShunts() {
	n, m, err := d.Shunts.NormalizeGeosite()
	switch {
	case err != nil:
		d.Logger.Warn("normalise geosite shunts failed", "error", err)
	case n > 0:
		d.Logger.Info(fmt.Sprintf("normalised %d geosite shunts, dropped %d copied entries", n, m),
			"shunts", n, "dropped_entries", m)
	}
}

// saveTracker writes the tracker state once more on shutdown, after the
// forwarder stopped, so the next start loads exactly what the set holds.
func (d *Daemon) saveTracker() {
	tracker := d.Forwarder.TrackerRef()
	if err := tracker.Save(); err != nil {
		d.Logger.Warn("save tracker state failed", "error", err)
		return
	}
	domains, ips := tracker.Count()
	d.Logger.Info("tracker state saved", "domains", domains, "ips", ips)
}
