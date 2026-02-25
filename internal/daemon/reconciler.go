package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/dns"
	"github.com/egorlepa/netshunt/internal/netfilter"
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
	Logger    *slog.Logger

	// lastDomains tracks the domain entries from the previous mutation
	// reconcile so we can detect removals.
	lastDomains map[string]struct{}
}

// NewReconciler creates a Reconciler from the given configuration.
func NewReconciler(cfg *config.Config, shunts *shunt.Store, forwarder *dns.Forwarder, logger *slog.Logger) *Reconciler {
	return &Reconciler{
		Config:      cfg,
		Shunts:      shunts,
		IPSet:       netfilter.NewIPSet(cfg.IPSet.TableName),
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

	// 3. Ensure ipset table exists.
	if err := r.IPSet.EnsureTable(ctx); err != nil {
		return fmt.Errorf("ensure ipset table: %w", err)
	}

	// 4. Flush ipset — full reconcile clears stale state.
	// DNS-resolved IPs will repopulate as queries flow through the forwarder.
	r.Forwarder.TrackerRef().Flush(ctx)

	// 5. Populate ipset with direct IP/CIDR entries.
	r.populateIPSet(ctx, entries)

	// 6. Teardown then re-setup iptables rules.
	_ = r.Mode.TeardownRules(ctx)
	if err := r.Mode.SetupRules(ctx); err != nil {
		return fmt.Errorf("setup iptables rules: %w", err)
	}

	r.Logger.Info("reconcile complete")
	return nil
}

// ApplyMutation updates the matcher and ipset after a shunt change.
// It diffs the domain list against the previous snapshot and removes
// stale domains from the tracker. Never flushes ipset or touches iptables.
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
	r.populateIPSet(ctx, entries)
	return nil
}

// populateIPSet adds direct IP/CIDR entries to ipset.
// Domain entries are handled by the DNS forwarder at query time.
func (r *Reconciler) populateIPSet(ctx context.Context, entries []shunt.Entry) {
	for _, e := range entries {
		switch e.Type() {
		case shunt.EntryIP, shunt.EntryCIDR:
			if err := r.IPSet.Add(ctx, e.Value); err != nil {
				r.Logger.Warn("failed to add to ipset", "entry", e.Value, "error", err)
			}
		}
	}
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
