package web

import (
	"context"
	"sync"
	"time"

	"github.com/egorlepa/netshunt/internal/healthcheck"
)

// healthFresh is how long a finished dashboard healthcheck run is served to
// further requests instead of starting a new one: the dashboard polls every
// 60 s, so any number of open tabs cost one run per minute.
const healthFresh = 50 * time.Second

// healthTimeout bounds one run; the checks carry their own shorter timeouts.
const healthTimeout = 60 * time.Second

// healthRunner runs the full healthcheck for the dashboard. Concurrent
// callers share one run: a request that arrives while a run is in progress
// waits for its result, and a result younger than healthFresh is returned
// as is. The run is detached from the requests, so a closed tab does not
// cancel it for the others.
type healthRunner struct {
	checks func() []healthcheck.Check
	now    func() time.Time

	mu      sync.Mutex
	running chan struct{} // closed when the current run finishes; nil when idle
	last    []healthcheck.Result
	lastAt  time.Time
}

func newHealthRunner(checks func() []healthcheck.Check) *healthRunner {
	return &healthRunner{checks: checks, now: time.Now}
}

// Results returns the latest results, running the checks when there is no
// fresh result. ctx only bounds the wait.
func (h *healthRunner) Results(ctx context.Context) ([]healthcheck.Result, time.Time, error) {
	h.mu.Lock()
	if h.last != nil && h.now().Sub(h.lastAt) < healthFresh {
		res, at := h.last, h.lastAt
		h.mu.Unlock()
		return res, at, nil
	}
	done := h.running
	if done == nil {
		done = make(chan struct{})
		h.running = done
		go h.run(done)
	}
	h.mu.Unlock()

	select {
	case <-done:
	case <-ctx.Done():
		return nil, time.Time{}, ctx.Err()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last, h.lastAt, nil
}

func (h *healthRunner) run(done chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), healthTimeout)
	defer cancel()
	res := healthcheck.RunAll(ctx, h.checks())
	h.mu.Lock()
	h.last, h.lastAt = res, h.now()
	h.running = nil
	h.mu.Unlock()
	close(done)
}
