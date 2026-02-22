package daemon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/dns"
	"github.com/egorlepa/netshunt/internal/group"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/routing"
	"github.com/egorlepa/netshunt/internal/service"
)

// DNS resolution is intentionally absent from the reconciler.
// dnsmasq's ipset= directive populates the bypass set on every DNS query in real-time,
// which is both correct and sufficient — a TCP connection cannot precede its DNS lookup.
// Direct IP/CIDR entries are added to ipset directly by populateIPSet.

// Reconciler performs the full state reconciliation:
//  1. Load all enabled entries from all enabled groups
//  2. Generate dnsmasq ipset config from domain entries
//  3. Add direct IP/CIDR entries to ipset (with TTL)
//  4. Verify/install iptables rules
//  5. Reload dnsmasq if config changed
type Reconciler struct {
	Config  *config.Config
	Groups  *group.Store
	IPSet   *netfilter.IPSet
	Dnsmasq *dns.DnsmasqConfig
	Mode    routing.Mode
	Logger  *slog.Logger
}


// NewReconciler creates a Reconciler from the given configuration.
func NewReconciler(cfg *config.Config, groups *group.Store, logger *slog.Logger) *Reconciler {
	return &Reconciler{
		Config:  cfg,
		Groups:  groups,
		IPSet:   netfilter.NewIPSet(cfg.IPSet.TableName),
		Dnsmasq: dns.NewDnsmasqConfig(cfg.IPSet.TableName),
		Mode:    routing.New(cfg, logger),
		Logger:  logger,
	}
}

// Reconcile performs a full state reconciliation.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	r.Logger.Info("starting full reconcile")

	// 1. Load all enabled entries.
	entries, err := r.Groups.EnabledEntries()
	if err != nil {
		return fmt.Errorf("load enabled entries: %w", err)
	}
	r.Logger.Info("loaded entries", "count", len(entries))

	// 2. Generate dnsmasq ipset config.
	changed, err := r.Dnsmasq.GenerateIPSetConfig(entries)
	if err != nil {
		return fmt.Errorf("generate dnsmasq config: %w", err)
	}
	if changed {
		r.Logger.Info("dnsmasq config updated, reloading")
		if err := service.Dnsmasq.Restart(ctx); err != nil {
			r.Logger.Warn("failed to restart dnsmasq", "error", err)
		}
	}

	// 3. Ensure ipset table exists.
	if err := r.IPSet.EnsureTable(ctx); err != nil {
		return fmt.Errorf("ensure ipset table: %w", err)
	}

	// 4. Populate ipset with direct IP/CIDR entries.
	r.populateIPSet(ctx, entries)

	// 5. Teardown then re-setup iptables rules. Teardown first ensures stale
	// rules (e.g. from a changed port) don't interfere.
	_ = r.Mode.TeardownRules(ctx)
	if err := r.Mode.SetupRules(ctx); err != nil {
		return fmt.Errorf("setup iptables rules: %w", err)
	}

	r.Logger.Info("reconcile complete")
	return nil
}

// ApplyMutation updates dnsmasq config and adds IPs to ipset after a group mutation
// (add/remove entry, enable/disable group). Never flushes ipset. Does not touch iptables.
func (r *Reconciler) ApplyMutation(ctx context.Context) error {
	entries, err := r.Groups.EnabledEntries()
	if err != nil {
		return fmt.Errorf("load entries: %w", err)
	}

	changed, err := r.Dnsmasq.GenerateIPSetConfig(entries)
	if err != nil {
		return fmt.Errorf("generate dnsmasq config: %w", err)
	}
	if changed {
		r.Logger.Info("dnsmasq config updated, reloading")
		if err := service.Dnsmasq.Restart(ctx); err != nil {
			r.Logger.Warn("failed to restart dnsmasq", "error", err)
		}
	}

	if err := r.IPSet.EnsureTable(ctx); err != nil {
		return fmt.Errorf("ensure ipset table: %w", err)
	}
	r.populateIPSet(ctx, entries)
	return nil
}

// populateIPSet adds direct IP/CIDR entries to ipset.
// Domain entries are handled by dnsmasq via ipset= directives at DNS query time.
func (r *Reconciler) populateIPSet(ctx context.Context, entries []group.Entry) {
	for _, e := range entries {
		switch e.Type() {
		case group.EntryIP, group.EntryCIDR:
			if err := r.IPSet.Add(ctx, e.Value); err != nil {
				r.Logger.Warn("failed to add to ipset", "entry", e.Value, "error", err)
			}
		}
	}
}
