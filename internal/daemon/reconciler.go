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

	"github.com/egorlepa/netshunt/internal/blocklist"
	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/dns"
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
// first run flushes the ipset instead of repairing it.
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

	// lastRejected is the set of entries the matcher refused on the previous
	// run, so the warning is logged when it changes, not on every mutation.
	lastRejected string

	// bootstrapped flips to true after the first Reconcile. The first run
	// flushes the kernel ipset to clear any stale entries left by a previous
	// daemon process - subsequent runs trust the in-memory tracker as source
	// of truth and never flush (no leak window).
	bootstrapped bool
}

// NewReconciler creates a Reconciler from the given configuration.
func NewReconciler(cfg *config.Live, shunts *shunt.Store, forwarder *dns.Forwarder, blocklistStore *blocklist.Store, logger *slog.Logger) *Reconciler {
	return &Reconciler{
		Config:    cfg,
		Shunts:    shunts,
		IPSet:     netfilter.NewIPSet(cfg.Load().IPSet.TableName),
		Forwarder: forwarder,
		Mode:      routing.New(cfg, logger),
		Blocklist: blocklistStore,
		Logger:    logger,
	}
}

// Reconcile reapplies the full state: matcher, full re-seed, static entries,
// ipset repair pass, iptables convergence, blocklist. The kernel ipset is flushed
// only on the very first call (cold start) to clear stale entries from a
// previous daemon process; subsequent reconciles preserve the in-memory
// tracker and instead diff the kernel ipset against it (Tracker.Repair).
func (r *Reconciler) Reconcile(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.Logger.Info("starting reconcile", "cold", !r.bootstrapped)

	if err := r.IPSet.EnsureTable(ctx); err != nil {
		return fmt.Errorf("ensure ipset table: %w", err)
	}

	tracker := r.Forwarder.TrackerRef()
	// The cold run flushes the kernel ipset, so the repair pass after it would
	// be a no-op; it is still needed if that flush failed.
	needRepair := r.bootstrapped
	if !r.bootstrapped {
		if err := tracker.Flush(ctx); err != nil {
			needRepair = true
		}
		r.bootstrapped = true
	}

	if err := r.applyMutationLocked(ctx, true); err != nil {
		return err
	}

	// Repair pass: the only place that heals external interference with the
	// kernel ipset (manual flush, failed del). Not run on ApplyMutation.
	if needRepair {
		added, removed, err := tracker.Repair(ctx)
		switch {
		case err != nil:
			r.Logger.Warn("ipset repair failed", "error", err)
		case added > 0 || removed > 0:
			r.Logger.Info("ipset repaired", "readded", added, "removed", removed)
		}
	}

	// Always converge iptables, also with an unchanged config: this is the
	// repair for rules NDM may have flushed. Nothing is torn down first, so
	// there is no window without redirect or DNS interception, and with
	// nothing to fix it only reads.
	if err := r.Mode.Reconcile(ctx); err != nil {
		return fmt.Errorf("reconcile rules: %w", err)
	}

	r.applyBlocklistLocked()

	r.Logger.Info("reconcile complete")
	return nil
}

// SwitchProxy converges only the iptables rules so they target
// cfg.Routing.ActivePort(): the redirect rules are replaced in place, the
// ipset and matcher are left alone.
func (r *Reconciler) SwitchProxy(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.Mode.Reconcile(ctx); err != nil {
		return fmt.Errorf("reconcile rules: %w", err)
	}
	return nil
}

// ApplyBlocklist rebuilds the forwarder's blocklist matcher from the store
// and re-applies the configured response kind. Cheap - just file reads.
func (r *Reconciler) ApplyBlocklist(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applyBlocklistLocked()
	return nil
}

func (r *Reconciler) applyBlocklistLocked() {
	cfg := r.Config.Load()
	r.Forwarder.SetBlockResponse(blockResponseFromConfig(cfg.Blocklist.Response))

	if r.Blocklist == nil || !cfg.Blocklist.Enabled {
		// Clear the matcher.
		r.Forwarder.Blocklist().Replace(nil)
		return
	}

	// Stream-build: each domain is scanned from disk, normalized in place,
	// and inserted directly into the new SuffixSet. No []string or
	// []shunt.Entry slice is materialised.
	counts := map[string]int{}
	total := r.Forwarder.Blocklist().Replace(func(add func(string)) {
		r.Blocklist.Stream(
			func(b []byte) { add(string(b)) },
			func(id string, c int) { counts[id] = c },
		)
	})

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
func (r *Reconciler) ApplyMutation(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.IPSet.EnsureTable(ctx); err != nil {
		return fmt.Errorf("ensure ipset table: %w", err)
	}
	return r.applyMutationLocked(ctx, false)
}

// applyMutationLocked is the body of ApplyMutation, callable from Reconcile
// which already holds r.mu and has ensured the ipset table. fullSeed re-seeds
// every cached domain the rules match, not only the newly matched ones.
//
// The tracker is keyed by DNS query name (www.example.net), not by rule
// (example.net), so removals are found by running every tracked domain
// through the new matcher: a suffix, keyword or regexp rule, a disabled or
// deleted shunt and a geosite update that drops domains all release exactly
// the IPs no remaining rule explains.
func (r *Reconciler) applyMutationLocked(ctx context.Context, fullSeed bool) (err error) {
	entries, err := r.Shunts.EnabledEntries()
	if err != nil {
		return fmt.Errorf("load entries: %w", err)
	}

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
		for _, ip := range s.ips {
			tracker.Track(ctx, s.domain, ip)
		}
	}

	// (e) Static IP/CIDR entries share the tracker's reference count with
	// DNS-tracked IPs: SetStatic adds/removes only what changes kernel
	// membership and flushes conntrack for exactly those members.
	tracker.SetStatic(ctx, r.staticEntries(entries))
	if err := ctx.Err(); err != nil {
		return err
	}

	if swept > 0 || len(seeds) > 0 {
		r.Logger.Debug("mutation applied", "swept_domains", swept, "seeded_domains", len(seeds))
	}
	return nil
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
