package dns

import (
	"context"
	"log/slog"
	"slices"
	"sync"

	"github.com/egorlepa/netshunt/internal/netfilter"
)

// Tracker maps domains to their resolved IPs and keeps the kernel ipset in
// sync. Reference counting ensures an IP is only removed from ipset when no
// domain needs it. IPs are retained until the domain is explicitly removed or
// the tracker is flushed — DNS TTL is intentionally ignored to prevent
// long-lived connections from losing routing mid-session.
type Tracker struct {
	mu      sync.RWMutex
	forward map[string][]string // domain → IPs (typically 1-4)
	reverse map[string][]string // IP → domains (typically 1-2)
	ipset   *netfilter.IPSet
	logger  *slog.Logger
}

// NewTracker creates a Tracker that manages the given ipset table.
func NewTracker(ipset *netfilter.IPSet, logger *slog.Logger) *Tracker {
	return &Tracker{
		forward: make(map[string][]string),
		reverse: make(map[string][]string),
		ipset:   ipset,
		logger:  logger,
	}
}

// Track records an IP for a domain. The IP is added to the kernel ipset and
// retained until the domain is removed or the tracker is flushed.
func (t *Tracker) Track(ctx context.Context, domain, ip string) {
	t.mu.Lock()
	ips := t.forward[domain]
	if !slices.Contains(ips, ip) {
		t.forward[domain] = append(ips, ip)
		refs := t.reverse[ip]
		if !slices.Contains(refs, domain) {
			t.reverse[ip] = append(refs, domain)
		}
	}
	t.mu.Unlock()

	if err := t.ipset.Add(ctx, ip); err != nil {
		t.logger.Warn("tracker: ipset add failed", "ip", ip, "error", err)
	}
}

// RemoveDomain removes all IPs associated with a domain. IPs that are no
// longer referenced by any domain are removed from ipset.
func (t *Tracker) RemoveDomain(ctx context.Context, domain string) {
	t.mu.Lock()
	ips := t.forward[domain]
	delete(t.forward, domain)

	var toRemove []string
	for _, ip := range ips {
		refs := t.reverse[ip]
		refs = slices.DeleteFunc(refs, func(d string) bool { return d == domain })
		if len(refs) == 0 {
			delete(t.reverse, ip)
			toRemove = append(toRemove, ip)
		} else {
			t.reverse[ip] = refs
		}
	}
	t.mu.Unlock()

	for _, ip := range toRemove {
		if err := t.ipset.Del(ctx, ip); err != nil {
			t.logger.Warn("tracker: ipset del failed", "ip", ip, "error", err)
		}
	}
}

// Flush clears all tracked state and flushes the ipset.
func (t *Tracker) Flush(ctx context.Context) {
	t.mu.Lock()
	t.forward = make(map[string][]string)
	t.reverse = make(map[string][]string)
	t.mu.Unlock()

	if err := t.ipset.Flush(ctx); err != nil {
		t.logger.Warn("tracker: ipset flush failed", "error", err)
	}
}

// Count returns the number of tracked domains and unique IPs.
func (t *Tracker) Count() (domains int, ips int) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.forward), len(t.reverse)
}
