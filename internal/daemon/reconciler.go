package daemon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/dns"
	"github.com/guras256/keenetic-split-tunnel/internal/group"
	"github.com/guras256/keenetic-split-tunnel/internal/netfilter"
	"github.com/guras256/keenetic-split-tunnel/internal/proxy"
	"github.com/guras256/keenetic-split-tunnel/internal/service"
)

// Reconciler performs the full state reconciliation:
//  1. Load all enabled entries from all enabled groups
//  2. Generate dnsmasq ipset config from domain entries
//  3. Add direct IP/CIDR entries to ipset
//  4. Resolve domain entries and pre-populate ipset
//  5. Verify/install iptables rules
//  6. Reload dnsmasq if config changed
type Reconciler struct {
	Config   *config.Config
	Groups   *group.Store
	IPSet    *netfilter.IPSet
	Dnsmasq  *dns.DnsmasqConfig
	Resolver *dns.Resolver
	Mode     proxy.TrafficMode
	Logger   *slog.Logger
}

// NewReconciler creates a Reconciler from the given configuration.
func NewReconciler(cfg *config.Config, groups *group.Store, logger *slog.Logger) *Reconciler {
	return &Reconciler{
		Config:   cfg,
		Groups:   groups,
		IPSet:    netfilter.NewIPSet(cfg.IPSet.TableName),
		Dnsmasq:  dns.NewDnsmasqConfig(cfg.IPSet.TableName),
		Resolver: dns.NewResolver("127.0.0.1"),
		Mode:     proxy.NewShadowsocks(cfg, logger),
		Logger:   logger,
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

	// 4. Populate ipset with direct IP/CIDR entries and pre-resolve domains.
	r.populateIPSet(ctx, entries)

	// 5. Setup iptables rules.
	if err := r.Mode.SetupRules(ctx); err != nil {
		return fmt.Errorf("setup iptables rules: %w", err)
	}

	r.Logger.Info("reconcile complete")
	return nil
}

// RefreshIPSet re-resolves all domains and refreshes ipset without touching dnsmasq config or iptables.
// Used for periodic re-resolve.
func (r *Reconciler) RefreshIPSet(ctx context.Context) error {
	r.Logger.Info("refreshing ipset")

	entries, err := r.Groups.EnabledEntries()
	if err != nil {
		return fmt.Errorf("load enabled entries: %w", err)
	}

	r.populateIPSet(ctx, entries)

	r.Logger.Info("ipset refresh complete")
	return nil
}

// populateIPSet adds entries to ipset:
//   - IP/CIDR entries are added directly
//   - Domain entries are resolved via DNS and resulting IPs are added
func (r *Reconciler) populateIPSet(ctx context.Context, entries []group.Entry) {
	for _, e := range entries {
		switch e.Type() {
		case group.EntryIP, group.EntryCIDR:
			if err := r.IPSet.Add(ctx, e.Value); err != nil {
				r.Logger.Warn("failed to add to ipset", "entry", e.Value, "error", err)
			}
		case group.EntryDomain:
			ips, err := r.Resolver.ResolveToStrings(ctx, e.Value)
			if err != nil {
				r.Logger.Warn("failed to resolve domain", "domain", e.Value, "error", err)
				continue
			}
			for _, ip := range ips {
				if err := r.IPSet.Add(ctx, ip); err != nil {
					r.Logger.Warn("failed to add resolved IP to ipset",
						"domain", e.Value, "ip", ip, "error", err)
				}
			}
		}
	}
}
