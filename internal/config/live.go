package config

import "sync/atomic"

// Live holds the daemon's current config. Web handlers replace it while the
// reconciler, scheduler, routing and dashboard read it from other goroutines,
// so a *Config returned by Load is a snapshot: never modify it, Store a new
// one instead.
type Live struct {
	p atomic.Pointer[Config]
}

// NewLive returns a Live holding cfg.
func NewLive(cfg *Config) *Live {
	l := &Live{}
	l.p.Store(cfg)
	return l
}

// Load returns the current config snapshot.
func (l *Live) Load() *Config { return l.p.Load() }

// Store publishes cfg as the current config. cfg must not be modified after.
func (l *Live) Store(cfg *Config) { l.p.Store(cfg) }
