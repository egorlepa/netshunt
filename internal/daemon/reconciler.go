package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"sync"

	"github.com/egorlepa/netshunt/internal/blocklist"
	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/dns"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/platform"
	"github.com/egorlepa/netshunt/internal/routing"
	"github.com/egorlepa/netshunt/internal/shunt"
)

// Reconciler performs state reconciliation between shunt entries, the DNS
// forwarder matcher, the kernel ipset, and iptables rules.
//
// Full reconcile: flush ipset, reload matcher, repopulate IP/CIDR entries,
// setup iptables. DNS-resolved IPs repopulate naturally as queries flow in.
//
// Mutation reconcile: update matcher (diff removed domains via tracker),
// ensure ipset table, populate IP/CIDRs.
type Reconciler struct {
	mu        sync.Mutex
	Config    *config.Config
	Shunts    *shunt.Store
	IPSet     *netfilter.IPSet
	Forwarder *dns.Forwarder
	Mode      routing.Mode
	Blocklist *blocklist.Store
	Logger    *slog.Logger

	// lastDomains/lastIPCIDRs track entries from the previous mutation reconcile
	// so we can detect additions and removals.
	lastDomains map[string]struct{}
	lastIPCIDRs map[string]struct{}

	// bootstrapped flips to true after the first Reconcile. The first run
	// flushes the kernel ipset to clear any stale entries left by a previous
	// daemon process — subsequent runs trust the in-memory tracker as source
	// of truth and never flush (no leak window).
	bootstrapped bool
}

// NewReconciler creates a Reconciler from the given configuration.
func NewReconciler(cfg *config.Config, shunts *shunt.Store, forwarder *dns.Forwarder, blocklistStore *blocklist.Store, logger *slog.Logger) *Reconciler {
	return &Reconciler{
		Config:      cfg,
		Shunts:      shunts,
		IPSet:       netfilter.NewIPSet(cfg.IPSet.TableName),
		Forwarder:   forwarder,
		Mode:        routing.New(cfg, logger),
		Blocklist:   blocklistStore,
		Logger:      logger,
		lastDomains: make(map[string]struct{}),
		lastIPCIDRs: make(map[string]struct{}),
	}
}

// Reconcile reapplies the full state: matcher, ipset diff, iptables rebuild,
// blocklist. The kernel ipset is flushed only on the very first call (cold
// start) to clear stale entries from a previous daemon process; subsequent
// reconciles preserve the in-memory tracker and avoid the leak window.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.Logger.Info("starting reconcile", "cold", !r.bootstrapped)

	if err := r.IPSet.EnsureTable(ctx); err != nil {
		return fmt.Errorf("ensure ipset table: %w", err)
	}

	if !r.bootstrapped {
		r.Forwarder.TrackerRef().Flush(ctx)
		r.bootstrapped = true
	}

	if err := r.applyMutationLocked(ctx); err != nil {
		return err
	}

	_ = r.Mode.TeardownRules(ctx)
	if err := r.Mode.SetupRules(ctx); err != nil {
		return fmt.Errorf("setup rules: %w", err)
	}

	r.applyBlocklistLocked()

	r.Logger.Info("reconcile complete")
	return nil
}

// SwitchProxy rebuilds only the iptables rules so they target
// cfg.Routing.ActivePort(). Skips ipset flush and matcher updates so DNS-resolved
// IPs stay in the set — otherwise a brief window after the switch would leak
// traffic directly (real IP) until the next DNS query repopulates the ipset.
func (r *Reconciler) SwitchProxy(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	_ = r.Mode.TeardownRules(ctx)
	if err := r.Mode.SetupRules(ctx); err != nil {
		return fmt.Errorf("setup rules: %w", err)
	}
	return nil
}

// ApplyBlocklist rebuilds the forwarder's blocklist matcher from the store
// and re-applies the configured response kind. Cheap — just file reads.
func (r *Reconciler) ApplyBlocklist(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applyBlocklistLocked()
	return nil
}

func (r *Reconciler) applyBlocklistLocked() {
	r.Forwarder.SetBlockResponse(blockResponseFromConfig(r.Config.Blocklist.Response))

	if r.Blocklist == nil || !r.Config.Blocklist.Enabled {
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
	return r.applyMutationLocked(ctx)
}

// applyMutationLocked is the body of ApplyMutation, callable from Reconcile
// which already holds r.mu and has ensured the ipset table.
func (r *Reconciler) applyMutationLocked(ctx context.Context) error {
	entries, err := r.Shunts.EnabledEntries()
	if err != nil {
		return fmt.Errorf("load entries: %w", err)
	}

	// Diff and remove stale domains from tracker.
	newDomains := domainSet(entries)
	for domain := range r.lastDomains {
		if _, ok := newDomains[domain]; !ok {
			r.Forwarder.TrackerRef().RemoveDomain(ctx, domain)
		}
	}

	// Update matcher and snapshot.
	r.Forwarder.UpdateMatcher(entries)
	r.lastDomains = newDomains

	// Seed from the resolve cache: for every domain the forwarder has recently
	// resolved that matches a (possibly newly-added) shunt rule, push its IPs
	// into the tracker. Track() handles ipset.Add + first-seen conntrack flush,
	// so the client's next request hits a live REDIRECT even if its browser/OS
	// DNS cache is still warm with the pre-shunt IP.
	matcher := r.Forwarder.Matcher()
	tracker := r.Forwarder.TrackerRef()
	r.Forwarder.ResolveCache().Range(func(domain string, ips []string) bool {
		if !matcher.Match(domain) {
			return true
		}
		for _, ip := range ips {
			tracker.Track(ctx, domain, ip)
		}
		return true
	})

	r.populateIPSet(ctx, entries)

	// Diff IP/CIDR entries:
	// - Added: flush conntrack so existing direct connections reopen through proxy.
	// - Removed: drop from ipset + flush conntrack so live proxied connections
	//   reopen and go direct.
	newIPCIDRs := ipCIDRSet(entries)
	for v := range newIPCIDRs {
		if _, ok := r.lastIPCIDRs[v]; ok {
			continue
		}
		r.flushConntrackForEntry(ctx, v)
	}
	for v := range r.lastIPCIDRs {
		if _, ok := newIPCIDRs[v]; ok {
			continue
		}
		if err := r.IPSet.Del(ctx, v); err != nil {
			r.Logger.Warn("ipset del failed", "entry", v, "error", err)
		}
		r.flushConntrackForEntry(ctx, v)
	}
	r.lastIPCIDRs = newIPCIDRs
	return nil
}

// flushConntrackForEntry drops conntrack entries whose orig-dst falls within
// the given IP or CIDR. Best-effort; logged at debug on failure (commonly
// "no matches" exit code).
func (r *Reconciler) flushConntrackForEntry(ctx context.Context, value string) {
	if _, ipnet, err := net.ParseCIDR(value); err == nil {
		mask := net.IP(ipnet.Mask).String()
		err := platform.RunSilent(ctx, "conntrack", "-D", "--orig-dst", ipnet.IP.String(), "--mask-dst", mask)
		if err != nil {
			r.Logger.Debug("conntrack flush returned non-zero (likely no matches)", "cidr", value, "error", err)
		}
		return
	}
	if err := platform.RunSilent(ctx, "conntrack", "-D", "--orig-dst", value); err != nil {
		r.Logger.Debug("conntrack flush returned non-zero (likely no matches)", "ip", value, "error", err)
	}
}

// populateIPSet adds direct IPv4 IP/CIDR entries to the ipset.
// IPv6 entries are skipped with a warning (unsupported). Domain entries are
// handled by the DNS forwarder at query time.
func (r *Reconciler) populateIPSet(ctx context.Context, entries []shunt.Entry) {
	for _, e := range entries {
		switch e.Type() {
		case shunt.EntryIP, shunt.EntryCIDR:
			if isIPv6Entry(e.Value) {
				r.Logger.Warn("skipping IPv6 entry (unsupported)", "entry", e.Value)
				continue
			}
			if err := r.IPSet.Add(ctx, e.Value); err != nil {
				r.Logger.Warn("failed to add to ipset", "entry", e.Value, "error", err)
			}
		}
	}
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

func domainSet(entries []shunt.Entry) map[string]struct{} {
	set := make(map[string]struct{})
	for _, e := range entries {
		if e.IsDomain() {
			set[e.DomainValue()] = struct{}{}
		}
	}
	return set
}

func ipCIDRSet(entries []shunt.Entry) map[string]struct{} {
	set := make(map[string]struct{})
	for _, e := range entries {
		switch e.Type() {
		case shunt.EntryIP, shunt.EntryCIDR:
			if isIPv6Entry(e.Value) {
				continue
			}
			set[e.Value] = struct{}{}
		}
	}
	return set
}
