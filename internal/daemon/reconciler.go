package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/dns"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/routing"
	"github.com/egorlepa/netshunt/internal/shunt"
)

// Reconciler performs state reconciliation between shunt entries, the DNS
// forwarder matcher, the kernel ipsets (v4 + v6), and iptables/ip6tables rules.
//
// Full reconcile: flush ipsets, reload matcher, repopulate IP/CIDR entries,
// setup iptables. DNS-resolved IPs repopulate naturally as queries flow in.
//
// Mutation reconcile: update matcher (diff removed domains via tracker),
// ensure ipset tables, populate IP/CIDRs.
type Reconciler struct {
	mu        sync.Mutex
	Config    *config.Config
	Shunts    *shunt.Store
	IPSet     *netfilter.IPSet
	IPSet6    *netfilter.IPSet
	Forwarder *dns.Forwarder
	Mode      routing.Mode
	Logger    *slog.Logger

	// lastDomains tracks the domain entries from the previous mutation
	// reconcile so we can detect removals.
	lastDomains map[string]struct{}
}

// NewReconciler creates a Reconciler from the given configuration.
func NewReconciler(cfg *config.Config, shunts *shunt.Store, forwarder *dns.Forwarder, logger *slog.Logger) *Reconciler {
	var ipset6 *netfilter.IPSet
	if cfg.IPv6 {
		ipset6 = netfilter.NewIPSet6(cfg.IPSet.TableName + "6")
	}
	return &Reconciler{
		Config:      cfg,
		Shunts:      shunts,
		IPSet:       netfilter.NewIPSet(cfg.IPSet.TableName),
		IPSet6:      ipset6,
		Forwarder:   forwarder,
		Mode:        routing.New(cfg, logger),
		Logger:      logger,
		lastDomains: make(map[string]struct{}),
	}
}

// Reconcile performs a full state reconciliation.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.Logger.Info("starting full reconcile")

	// 1. Load all enabled entries.
	entries, err := r.Shunts.EnabledEntries()
	if err != nil {
		return fmt.Errorf("load enabled entries: %w", err)
	}
	r.Logger.Info("loaded entries", "count", len(entries))

	// 2. Update forwarder matcher with domain entries.
	r.Forwarder.UpdateMatcher(entries)
	r.lastDomains = domainSet(entries)

	// 3. Ensure ipset tables exist.
	if err := r.IPSet.EnsureTable(ctx); err != nil {
		return fmt.Errorf("ensure ipset table: %w", err)
	}
	if r.IPSet6 != nil {
		if err := r.IPSet6.EnsureTable(ctx); err != nil {
			return fmt.Errorf("ensure ipset6 table: %w", err)
		}
	}

	// 4. Flush ipsets — full reconcile clears stale state.
	// DNS-resolved IPs will repopulate as queries flow through the forwarder.
	r.Forwarder.TrackerRef().Flush(ctx)

	// 5. Populate ipsets with direct IP/CIDR entries.
	r.populateIPSet(ctx, entries)

	// 6. Teardown then re-setup iptables/ip6tables rules.
	_ = r.Mode.TeardownRules(ctx)
	if err := r.Mode.SetupRules(ctx); err != nil {
		return fmt.Errorf("setup rules: %w", err)
	}

	r.Logger.Info("reconcile complete")
	return nil
}

// ApplyMutation updates the matcher and ipsets after a shunt change.
// It diffs the domain list against the previous snapshot and removes
// stale domains from the tracker. Never flushes ipsets or touches iptables.
func (r *Reconciler) ApplyMutation(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	entries, err := r.Shunts.EnabledEntries()
	if err != nil {
		return fmt.Errorf("load entries: %w", err)
	}

	// Build new domain set and detect removals.
	newDomains := domainSet(entries)
	for domain := range r.lastDomains {
		if _, ok := newDomains[domain]; !ok {
			r.Forwarder.TrackerRef().RemoveDomain(ctx, domain)
		}
	}

	// Update matcher and snapshot.
	r.Forwarder.UpdateMatcher(entries)
	r.lastDomains = newDomains

	if err := r.IPSet.EnsureTable(ctx); err != nil {
		return fmt.Errorf("ensure ipset table: %w", err)
	}
	if r.IPSet6 != nil {
		if err := r.IPSet6.EnsureTable(ctx); err != nil {
			return fmt.Errorf("ensure ipset6 table: %w", err)
		}
	}
	r.populateIPSet(ctx, entries)
	return nil
}

// populateIPSet adds direct IP/CIDR entries to the appropriate ipset (v4 or v6).
// Domain entries are handled by the DNS forwarder at query time.
func (r *Reconciler) populateIPSet(ctx context.Context, entries []shunt.Entry) {
	for _, e := range entries {
		switch e.Type() {
		case shunt.EntryIP, shunt.EntryCIDR:
			if r.IPSet6 == nil && isIPv6Entry(e.Value) {
				continue // skip IPv6 entries when IPv6 is disabled
			}
			ipset := r.ipsetFor(e.Value)
			if err := ipset.Add(ctx, e.Value); err != nil {
				r.Logger.Warn("failed to add to ipset", "entry", e.Value, "error", err)
			}
		}
	}
}

// ipsetFor returns the appropriate ipset for the given IP or CIDR string.
func (r *Reconciler) ipsetFor(entry string) *netfilter.IPSet {
	if isIPv6Entry(entry) && r.IPSet6 != nil {
		return r.IPSet6
	}
	return r.IPSet
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
