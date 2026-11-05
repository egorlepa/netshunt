package web

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/egorlepa/netshunt/internal/healthcheck"
)

// healthFresh is how long a finished healthcheck run is served to further
// requests instead of starting a new one: the dashboard polls every 60 s
// and the background run fires every 60 s, so any number of open tabs plus
// the background cost one run per minute.
const healthFresh = 50 * time.Second

// healthTimeout bounds one run; the checks carry their own shorter timeouts.
const healthTimeout = 60 * time.Second

// healthInterval is the period of the background run that keeps the
// healthcheck metrics (and the dashboard's base checks) current.
const healthInterval = 60 * time.Second

// healthRunner runs the healthcheck for the dashboard and the background
// loop. The checks are split into two groups with separate caches:
//
//   - base: every check except the proxy connectivity ones. The background
//     loop refreshes it once a minute; /metrics reads its last result.
//   - connectivity: the proxy connectivity checks, which insert a nat
//     OUTPUT rule and send real requests through the proxy. Only the
//     dashboard runs them (on demand, when its cached result is stale), so
//     an idle daemon never touches iptables or the proxy for health.
//
// The dashboard asks for both groups and gets them merged in check order:
// base usually comes fresh from the background run, connectivity runs
// itself. Within a group concurrent callers share one run: a request that
// arrives while a run is in progress waits for its result, and a result
// younger than healthFresh is returned as is. Runs are detached from the
// requests, so a closed tab does not cancel them for the others.
type healthRunner struct {
	checks func() []healthcheck.Check
	now    func() time.Time

	base, conn healthGroup
}

type healthGroup struct {
	connectivity bool // which checks this group runs

	mu      sync.Mutex
	running chan struct{} // closed when the current run finishes; nil when idle
	last    []healthcheck.Result
	idx     []int // position of each result in the full check list
	lastAt  time.Time
}

func newHealthRunner(checks func() []healthcheck.Check) *healthRunner {
	h := &healthRunner{checks: checks, now: time.Now}
	h.conn.connectivity = true
	return h
}

// Results returns the latest results of every check (both groups), running
// each group that has no fresh result. ctx only bounds the wait. The time is
// that of the older group's run.
func (h *healthRunner) Results(ctx context.Context) ([]healthcheck.Result, time.Time, error) {
	bd := h.begin(&h.base)
	cd := h.begin(&h.conn)
	for _, d := range []chan struct{}{bd, cd} {
		if err := wait(ctx, d); err != nil {
			return nil, time.Time{}, err
		}
	}
	type pair struct {
		i int
		r healthcheck.Result
	}
	var all []pair
	at := h.now()
	for _, g := range []*healthGroup{&h.base, &h.conn} {
		g.mu.Lock()
		for k, r := range g.last {
			all = append(all, pair{g.idx[k], r})
		}
		if g.lastAt.Before(at) {
			at = g.lastAt
		}
		g.mu.Unlock()
	}
	slices.SortStableFunc(all, func(a, b pair) int { return a.i - b.i })
	res := make([]healthcheck.Result, len(all))
	for k, p := range all {
		res[k] = p.r
	}
	return res, at, nil
}

// BaseResults returns the latest results of the checks without the proxy
// connectivity ones, running them when there is no fresh result.
func (h *healthRunner) BaseResults(ctx context.Context) ([]healthcheck.Result, time.Time, error) {
	if err := wait(ctx, h.begin(&h.base)); err != nil {
		return nil, time.Time{}, err
	}
	h.base.mu.Lock()
	defer h.base.mu.Unlock()
	return h.base.last, h.base.lastAt, nil
}

// LastBase returns the last finished base results without running anything
// (nil before the first run).
func (h *healthRunner) LastBase() ([]healthcheck.Result, time.Time) {
	h.base.mu.Lock()
	defer h.base.mu.Unlock()
	return h.base.last, h.base.lastAt
}

// Loop refreshes the base group every healthInterval until ctx ends, the
// first time right away.
func (h *healthRunner) Loop(ctx context.Context) {
	t := time.NewTicker(healthInterval)
	defer t.Stop()
	for {
		_, _, _ = h.BaseResults(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// begin returns nil when g has a fresh result, otherwise the channel of the
// run in progress, starting one if needed.
func (h *healthRunner) begin(g *healthGroup) chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.last != nil && h.now().Sub(g.lastAt) < healthFresh {
		return nil
	}
	if g.running == nil {
		g.running = make(chan struct{})
		go h.run(g, g.running)
	}
	return g.running
}

func wait(ctx context.Context, done chan struct{}) error {
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *healthRunner) run(g *healthGroup, done chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), healthTimeout)
	defer cancel()
	var checks []healthcheck.Check
	var idx []int
	for i, c := range h.checks() {
		if c.Connectivity == g.connectivity {
			checks = append(checks, c)
			idx = append(idx, i)
		}
	}
	res := healthcheck.RunAll(ctx, checks)
	g.mu.Lock()
	g.last, g.idx, g.lastAt = res, idx, h.now()
	g.running = nil
	g.mu.Unlock()
	close(done)
}
