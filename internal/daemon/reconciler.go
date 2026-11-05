package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/egorlepa/netshunt/internal/blocklist"
	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/dns"
	"github.com/egorlepa/netshunt/internal/metrics"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/routing"
	"github.com/egorlepa/netshunt/internal/shunt"
)

// Reconciler performs state reconciliation between shunt entries, the DNS
// forwarder matcher, the kernel ipset, and iptables rules.
//
// The kernel ipset is owned by the DNS tracker: both DNS-resolved IPs and
// static IP/CIDR entries go through it, so one reference count decides when a
// member leaves the set.
//
// Full reconcile: reload matcher, re-seed every matched cached domain, sync
// static entries, then a repair pass diffs the kernel ipset against the
// tracker (one `ipset list`), converge iptables (Mode.Reconcile). The cold
// first run loads the persisted tracker state first (filtered through the
// current rules, installed without exec), so the repair pass keeps what the
// kernel already holds: the ipset is never flushed on start.
//
// Mutation reconcile: update matcher, sweep every tracked domain the new
// rules no longer match, seed newly matched cached domains, sync static
// entries.
type Reconciler struct {
	mu        sync.Mutex
	Config    *config.Live
	Shunts    *shunt.Store
	IPSet     *netfilter.IPSet
	Forwarder *dns.Forwarder
	Mode      routing.Mode
	Blocklist *blocklist.Store
	Logger    *slog.Logger

	// seedAll forces the next mutation to seed every matched cached domain:
	// set when a mutation stopped before its seeding finished, because the
	// next one would otherwise consider those domains already matched.
	seedAll bool

	// lastGeositeMissing is the set of enabled geosite shunts without data
	// on the previous run, logged when it changes.
	lastGeositeMissing string

	// lastRejected is the set of entries the matcher refused on the previous
	// run, so the warning is logged when it changes, not on every mutation.
	lastRejected string

	// bootstrapped flips to true after the first Reconcile, which loads the
	// persisted tracker state.
	bootstrapped bool

	// blocklistKey identifies the inputs of the installed blocklist matcher:
	// "disabled", or "enabled" plus the store fingerprint (enabled sources,
	// cache file size and mtime). Empty until the first apply.
	blocklistKey string

	// Metrics, read at scrape time without r.mu.
	stats           reconcileStats
	blocklistCounts atomic.Pointer[[]sourceCount]
}

// reconcileStats counts reconciles per kind and the repair pass results.
type reconcileStats struct {
	mutation, full             reconcileKindStats
	repairAdded, repairRemoved metrics.Counter
}

type reconcileKindStats struct {
	ok, failed   metrics.Counter
	lastDuration metrics.Gauge // seconds, of the last run, ok or not
	lastSuccess  metrics.Gauge // unix seconds, 0 until the first success
}

func (k *reconcileKindStats) record(start time.Time, err error) {
	end := time.Now()
	k.lastDuration.Set(end.Sub(start).Seconds())
	if err != nil {
		k.failed.Inc()
		return
	}
	k.ok.Inc()
	k.lastSuccess.Set(float64(end.UnixNano()) / 1e9)
}

// sourceCount is the number of domains one enabled blocklist source
// contributed to the installed matcher (0 when its file is missing or
// empty; the domains read before an error otherwise).
type sourceCount struct {
	id    string
	count int
}

// NewReconciler creates a Reconciler from the given configuration.
// ipset is the same set the forwarder's tracker drives.
func NewReconciler(cfg *config.Live, shunts *shunt.Store, forwarder *dns.Forwarder, blocklistStore *blocklist.Store, ipset *netfilter.IPSet, logger *slog.Logger) *Reconciler {
	return &Reconciler{
		Config:    cfg,
		Shunts:    shunts,
		IPSet:     ipset,
		Forwarder: forwarder,
		Mode:      routing.New(cfg, logger),
		Blocklist: blocklistStore,
		Logger:    logger,
	}
}

// Reconcile reapplies the full state: matcher, full re-seed, static entries,
// ipset repair pass, iptables convergence, blocklist. The very first call
// (cold start) first loads the tracker state the previous daemon saved; the
// repair pass then deletes kernel members nothing explains and re-adds the
// ones the kernel lacks (all of them after a reboot). The kernel ipset is
// never flushed, so clients holding cached IPs keep going through the proxy
// across a daemon restart.
func (r *Reconciler) Reconcile(ctx context.Context) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	defer func(start time.Time) { r.stats.full.record(start, err) }(time.Now())

	r.Logger.Info("starting reconcile", "cold", !r.bootstrapped)

	if err := r.IPSet.EnsureTable(ctx); err != nil {
		return fmt.Errorf("ensure ipset table: %w", err)
	}

	tracker := r.Forwarder.TrackerRef()
	if !r.bootstrapped {
		if err := r.loadTrackerLocked(); err != nil {
			return err
		}
		r.bootstrapped = true
	}

	if err := r.applyMutationLocked(ctx, true); err != nil {
		return err
	}

	// Repair pass: the only place that heals external interference with the
	// kernel ipset (manual flush, failed del) and, on the cold run, the
	// difference between the loaded state and the kernel. Not run on
	// ApplyMutation.
	added, removed, repairErr := tracker.Repair(ctx)
	r.stats.repairAdded.Add(uint64(added))
	r.stats.repairRemoved.Add(uint64(removed))
	switch {
	case repairErr != nil:
		r.Logger.Warn("ipset repair failed", "error", repairErr)
	case added > 0 || removed > 0:
		r.Logger.Info("ipset repaired", "readded", added, "removed", removed)
	}
	cache := r.Forwarder.ResolveCache()
	r.Logger.Info("resolve cache", "entries", cache.Len(), "capacity", cache.Cap())

	// Always converge iptables, also with an unchanged config: this is the
	// repair for rules NDM may have flushed. Nothing is torn down first, so
	// there is no window without redirect or DNS interception, and with
	// nothing to fix it only reads.
	// A failure (e.g. TPROXY unavailable) fails the reconcile; the blocklist
	// does not depend on the rules and is applied either way.
	modeErr := r.Mode.Reconcile(ctx)

	r.applyBlocklistLocked()

	if modeErr != nil {
		return fmt.Errorf("reconcile rules: %w", modeErr)
	}
	r.Logger.Info("reconcile complete")
	return nil
}

// loadTrackerLocked is the cold-start half of the tracker persistence: the
// saved domain -> IPs map is filtered through a matcher built from the
// current shunts (the forwarder's matcher is still empty here), and the
// survivors plus the static entries are installed into the tracker without
// exec, as believed present. The repair pass that follows makes the kernel
// equal to that. A missing or corrupt file is an empty state.
func (r *Reconciler) loadTrackerLocked() error {
	entries, err := r.Shunts.EnabledEntries()
	if err != nil {
		return fmt.Errorf("load entries: %w", err)
	}
	matcher := dns.NewMatcher()
	matcher.Update(entries)
	tracker := r.Forwarder.TrackerRef()
	res, err := tracker.LoadPersisted(matcher.Match)
	if err != nil {
		r.Logger.Warn("tracker state not loaded, starting empty", "error", err)
	} else {
		r.Logger.Info("tracker state loaded", "domains", res.Domains, "ips", res.IPs, "dropped_domains", res.Dropped)
	}
	tracker.PresumeStatic(r.staticEntries(entries))
	return nil
}

// ApplyBlocklist re-applies the configured response kind and rebuilds the
// forwarder's blocklist matcher from the store when its inputs changed.
func (r *Reconciler) ApplyBlocklist(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applyBlocklistLocked()
	return nil
}

// applyBlocklistLocked always sets the response kind, which does not affect
// the matcher, then rebuilds the matcher only when (enabled, fingerprint)
// differs from the last applied build: a rebuild of a 200k-domain list costs
// about 0.7 s and a 13 MB heap spike on the router, and a full reconcile or a
// response-kind change would otherwise pay it every time.
func (r *Reconciler) applyBlocklistLocked() {
	cfg := r.Config.Load()
	r.Forwarder.SetBlockResponse(blockResponseFromConfig(cfg.Blocklist.Response))

	key := "disabled"
	if r.Blocklist != nil && cfg.Blocklist.Enabled {
		// Taken before streaming: a download renamed in during the build
		// changes the fingerprint, so the next apply rebuilds again.
		key = "enabled\x00" + r.Blocklist.Fingerprint()
	}
	if key == r.blocklistKey {
		r.Logger.Debug("blocklist unchanged")
		return
	}

	if key == "disabled" {
		r.blocklistCounts.Store(nil)
		r.Forwarder.Blocklist().Replace(nil)
		r.blocklistKey = key
		r.Logger.Info("blocklist cleared")
		return
	}

	// Stream-build: each domain is scanned from disk, normalized in place,
	// and copied straight into the new SuffixSet. No per-domain string, no
	// []string or []shunt.Entry slice is materialised.
	counts := map[string]int{}
	var perSource []sourceCount
	total := r.Forwarder.Blocklist().Replace(func(add func([]byte)) {
		r.Blocklist.Stream(add, func(id string, c int, err error) {
			counts[id] = c
			perSource = append(perSource, sourceCount{id, c})
			if err != nil {
				r.Logger.Warn("blocklist source unreadable", "id", id, "error", err)
			}
		})
	})
	r.blocklistKey = key
	r.blocklistCounts.Store(&perSource)

	// Force reclamation of the old matcher rules + any transient parse
	// allocations now, rather than waiting on the GC pacer. On a router the
	// heap high-water mark matters far more than throughput.
	runtime.GC()

	r.Logger.Info("blocklist applied", "domains", total, "per_source", counts)
}

func blockResponseFromConfig(r config.BlocklistResponse) dns.BlockResponse {
	switch r {
	case config.BlocklistResponseNoData:
		return dns.BlockNoData
	case config.BlocklistResponseZero:
		return dns.BlockZero
	default:
		return dns.BlockNXDomain
	}
}

// ApplyMutation updates the matcher and ipset after a shunt change.
// It diffs against the previous snapshot. Never touches iptables.
func (r *Reconciler) ApplyMutation(ctx context.Context) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	defer func(start time.Time) { r.stats.mutation.record(start, err) }(time.Now())
	if err := r.IPSet.EnsureTable(ctx); err != nil {
		return fmt.Errorf("ensure ipset table: %w", err)
	}
	return r.applyMutationLocked(ctx, false)
}

// applyMutationLocked is the body of ApplyMutation, callable from Reconcile
// which already holds r.mu and has ensured the ipset table. fullSeed re-seeds
// every cached domain the rules match, not only the newly matched ones.
//
// The tracker is keyed by the DNS name a rule matched (the query name
// www.example.net, or the name of its CNAME chain that matched), not by
// rule (example.net), so removals are found by running every tracked domain
// through the new matcher: a suffix, keyword or regexp rule, a disabled or
// deleted shunt and a geosite update that drops domains all release exactly
// the IPs no remaining rule explains.
func (r *Reconciler) applyMutationLocked(ctx context.Context, fullSeed bool) (err error) {
	entries, err := r.Shunts.EnabledEntries()
	if err != nil {
		return fmt.Errorf("load entries: %w", err)
	}
	shuntsNow, _ := r.Shunts.List()
	r.warnGeositeMissing()

	tracker := r.Forwarder.TrackerRef()
	// Members whose del failed on an earlier run (cancelled context) are
	// still in the kernel; drop them first.
	tracker.RetryOrphans(ctx)

	fullSeed = fullSeed || r.seedAll
	r.seedAll = true
	defer func() {
		if err == nil {
			r.seedAll = false
		}
	}()

	// (a) previous rules, (b) new rules first, so a DNS answer that arrives
	// during the sweep is already judged by them.
	prev := r.Forwarder.Matcher().Snapshot()
	rejected := r.Forwarder.UpdateMatcher(entries)
	for _, e := range entries {
		if !e.IsDomain() && !e.Valid() { // IPv6 statics, skipped by staticEntries
			rejected = append(rejected, e)
		}
	}
	r.warnRejected(rejected)
	matcher := r.Forwarder.Matcher()

	// (c) Sweep: a tracked domain the new rules do not match loses its IPs.
	// A domain another rule still matches is simply not swept.
	swept := 0
	for _, domain := range tracker.Domains() {
		if matcher.Match(domain) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("sweep: %w", err)
		}
		tracker.RemoveDomain(ctx, domain)
		swept++
	}

	// (d) Seed from the resolve cache: for every domain the forwarder has
	// recently resolved that a newly added rule matches, push its IPs into
	// the tracker. Track() handles ipset.Add + first-seen conntrack flush, so
	// the client's next request hits a live REDIRECT even if its browser/OS
	// DNS cache is still warm with the pre-shunt IP.
	//
	// On a shunt mutation, domains the previous rules already matched were
	// tracked at query time, so only the difference is seeded: Track() execs
	// ipset per IP, and re-seeding the whole cache took about a minute on the
	// router. A full Reconcile (startup, WAN hook, settings) still re-seeds
	// everything as a repair pass. The pairs are collected first and tracked
	// outside Range, which holds the cache lock that every DNS response needs.
	type seed struct {
		domain string
		ips    []string
	}
	var seeds []seed
	r.Forwarder.ResolveCache().Range(func(domain string, ips []string) bool {
		if !matcher.Match(domain) {
			return true
		}
		if fullSeed || !prev.Match(domain) {
			seeds = append(seeds, seed{domain, slices.Clone(ips)})
		}
		return true
	})
	for _, s := range seeds {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("seed: %w", err)
		}
		tracker.TrackMany(ctx, s.domain, s.ips)
	}

	// (e) Static IP/CIDR entries share the tracker's reference count with
	// DNS-tracked IPs: SetStatic adds/removes only what changes kernel
	// membership and flushes conntrack for exactly those members.
	staticAdded, staticRemoved := tracker.SetStatic(ctx, r.staticEntries(entries))
	if err := ctx.Err(); err != nil {
		return err
	}

	// One Info line per mutation that changed anything: this is the audit
	// trail for "why did the ipset change", and the only record of what
	// a toggle did once the request is gone.
	if swept > 0 || len(seeds) > 0 || staticAdded > 0 || staticRemoved > 0 {
		enabled := 0
		for _, sh := range shuntsNow {
			if sh.Enabled {
				enabled++
			}
		}
		r.Logger.Info("mutation applied",
			"full", fullSeed, "enabled_shunts", enabled, "entries", len(entries),
			"swept_domains", swept, "seeded_domains", len(seeds),
			"static_added", staticAdded, "static_removed", staticRemoved,
			"members", tracker.Members())
	}
	return nil
}

// warnGeositeMissing logs the enabled geosite shunts that contribute no
// entries (database missing or category not in it), once per change.
func (r *Reconciler) warnGeositeMissing() {
	missing, err := r.Shunts.GeositeMissing()
	if err != nil {
		return
	}
	var names []string
	for _, sh := range missing {
		names = append(names, sh.Name+" ("+sh.Source+")")
	}
	key := strings.Join(names, "\x00")
	if key == r.lastGeositeMissing {
		return
	}
	r.lastGeositeMissing = key
	if len(names) > 0 {
		r.Logger.Warn("geosite shunts without data, not applied", "shunts", strings.Join(names, ", "))
	}
}

// warnRejected logs the entries the matcher could not apply (present in
// shunts.yaml from before validation, or hand-edited), once per change.
func (r *Reconciler) warnRejected(rejected []shunt.Entry) {
	var b strings.Builder
	for _, e := range rejected {
		b.WriteString(e.Shunt + "\x00" + e.Value + "\x00")
	}
	if b.String() == r.lastRejected {
		return
	}
	r.lastRejected = b.String()
	for _, e := range rejected {
		reason := "cannot be applied"
		var ie *shunt.InvalidEntryError
		if errors.As(shunt.Validate(e.Value), &ie) {
			reason = ie.Reason
		}
		r.Logger.Warn("shunt entry not applied", "shunt", e.Shunt, "value", e.Value, "reason", reason)
	}
}

// staticEntries returns the IPv4 IP/CIDR entry values. IPv6 entries are
// skipped with a warning (unsupported). Domain entries are handled by the DNS
// forwarder at query time.
func (r *Reconciler) staticEntries(entries []shunt.Entry) []string {
	var out []string
	for _, e := range entries {
		switch e.Type() {
		case shunt.EntryIP, shunt.EntryCIDR:
			if isIPv6Entry(e.Value) {
				continue // reported by warnRejected
			}
			out = append(out, e.Value)
		}
	}
	return out
}

// isIPv6Entry reports whether the given IP or CIDR string is IPv6.
func isIPv6Entry(entry string) bool {
	if _, cidr, err := net.ParseCIDR(entry); err == nil {
		return cidr.IP.To4() == nil
	}
	if ip := net.ParseIP(entry); ip != nil {
		return ip.To4() == nil
	}
	return false
}
