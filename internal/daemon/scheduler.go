package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/egorlepa/netshunt/internal/config"
)

// UpdateJobs is the surface the scheduler needs from the rest of the daemon.
// Each method must be safe to call from a background goroutine.
type UpdateJobs interface {
	UpdateAllBlocklistSources(ctx context.Context) (success, failed int)
	UpdateGeosite(ctx context.Context) (refreshed int, err error)
}

// Scheduler runs periodic blocklist + geosite refreshes. Per-job mutex
// prevents overlapping runs if a previous tick is still in flight.
type Scheduler struct {
	cfg    *config.Config
	jobs   UpdateJobs
	logger *slog.Logger

	mu   sync.Mutex // guards cron
	cron *cron.Cron

	blMu sync.Mutex
	gsMu sync.Mutex
}

// NewScheduler creates a Scheduler bound to the given config + job runner.
// Use Start/Stop to control lifecycle.
func NewScheduler(cfg *config.Config, jobs UpdateJobs, logger *slog.Logger) *Scheduler {
	return &Scheduler{
		cfg:    cfg,
		jobs:   jobs,
		logger: logger,
	}
}

// Start registers cron entries (always, regardless of current enabled flag —
// the per-tick handlers re-check the flag at runtime, so toggling auto-update
// in the UI takes effect immediately).
//
// No catch-up runs on boot — jobs only fire at their scheduled time.
func (s *Scheduler) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rebuildLocked()
}

// Reconfigure stops the current cron, rebuilds it from the latest config
// (read fresh from s.cfg), and restarts. Safe to call any time; in-flight
// jobs are allowed to finish first.
func (s *Scheduler) Reconfigure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cron != nil {
		<-s.cron.Stop().Done()
	}
	return s.rebuildLocked()
}

// rebuildLocked must be called with s.mu held.
func (s *Scheduler) rebuildLocked() error {
	blSched := s.cfg.Blocklist.AutoUpdate.Schedule
	if blSched == "" {
		blSched = config.DefaultBlocklistSchedule
	}
	gsSched := s.cfg.Geosite.AutoUpdate.Schedule
	if gsSched == "" {
		gsSched = config.DefaultGeositeSchedule
	}

	c := cron.New()
	if _, err := c.AddFunc(blSched, s.runBlocklist); err != nil {
		return fmt.Errorf("schedule blocklist auto-update (%q): %w", blSched, err)
	}
	if _, err := c.AddFunc(gsSched, s.runGeosite); err != nil {
		return fmt.Errorf("schedule geosite auto-update (%q): %w", gsSched, err)
	}
	c.Start()
	s.cron = c

	s.logger.Info("scheduler running",
		"blocklist_enabled", s.cfg.Blocklist.AutoUpdate.Enabled,
		"blocklist_schedule", blSched,
		"geosite_enabled", s.cfg.Geosite.AutoUpdate.Enabled,
		"geosite_schedule", gsSched,
	)
	return nil
}

// Stop waits for in-flight cron jobs to finish, then returns.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cron == nil {
		return
	}
	ctx := s.cron.Stop()
	select {
	case <-ctx.Done():
	case <-time.After(30 * time.Second):
		s.logger.Warn("scheduler stop timed out waiting for jobs")
	}
	s.cron = nil
}

func (s *Scheduler) runBlocklist() {
	if !s.cfg.Blocklist.AutoUpdate.Enabled {
		return
	}
	if !s.blMu.TryLock() {
		s.logger.Info("blocklist auto-update skipped: previous run still in progress")
		return
	}
	defer s.blMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	start := time.Now()
	success, failed := s.jobs.UpdateAllBlocklistSources(ctx)
	s.logger.Info("blocklist auto-update finished",
		"success", success, "failed", failed, "duration", time.Since(start))
}

func (s *Scheduler) runGeosite() {
	if !s.cfg.Geosite.AutoUpdate.Enabled {
		return
	}
	if !s.gsMu.TryLock() {
		s.logger.Info("geosite auto-update skipped: previous run still in progress")
		return
	}
	defer s.gsMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	start := time.Now()
	refreshed, err := s.jobs.UpdateGeosite(ctx)
	if err != nil {
		s.logger.Warn("geosite auto-update failed", "error", err, "duration", time.Since(start))
		return
	}
	s.logger.Info("geosite auto-update finished",
		"refreshed_shunts", refreshed, "duration", time.Since(start))
}
