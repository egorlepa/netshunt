package dns

import (
	"context"
	"log/slog"
	"net"
	"slices"
	"sync"

	"github.com/egorlepa/netshunt/internal/netfilter"
)

// Tracker maps domains to their resolved IPs and keeps the kernel ipsets in
// sync. Reference counting ensures an IP is only removed from ipset when no
// domain needs it. IPs are retained until the domain is explicitly removed or
// the tracker is flushed — DNS TTL is intentionally ignored to prevent
// long-lived connections from losing routing mid-session.
//
// IPv4 and IPv6 addresses are routed to separate ipset tables automatically.
type Tracker struct {
	mu      sync.RWMutex
	forward map[string][]string // domain → IPs (typically 1-4)
	reverse map[string][]string // IP → domains (typically 1-2)
	ipset4  *netfilter.IPSet
	ipset6  *netfilter.IPSet
	logger  *slog.Logger
}

// NewTracker creates a Tracker that manages the given ipset tables.
func NewTracker(ipset4, ipset6 *netfilter.IPSet, logger *slog.Logger) *Tracker {
	return &Tracker{
		forward: make(map[string][]string),
		reverse: make(map[string][]string),
		ipset4:  ipset4,
		ipset6:  ipset6,
		logger:  logger,
	}
}

// Track records an IP for a domain. The IP is added to the appropriate kernel
// ipset (v4 or v6) and retained until the domain is removed or the tracker is
// flushed.
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

	if err := t.ipsetFor(ip).Add(ctx, ip); err != nil {
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
		if err := t.ipsetFor(ip).Del(ctx, ip); err != nil {
			t.logger.Warn("tracker: ipset del failed", "ip", ip, "error", err)
		}
	}
}

// Flush clears all tracked state and flushes both ipsets.
func (t *Tracker) Flush(ctx context.Context) {
	t.mu.Lock()
	t.forward = make(map[string][]string)
	t.reverse = make(map[string][]string)
	t.mu.Unlock()

	if err := t.ipset4.Flush(ctx); err != nil {
		t.logger.Warn("tracker: ipset4 flush failed", "error", err)
	}
	if t.ipset6 != nil {
		if err := t.ipset6.Flush(ctx); err != nil {
			t.logger.Warn("tracker: ipset6 flush failed", "error", err)
		}
	}
}

// Count returns the number of tracked domains and unique IPs.
func (t *Tracker) Count() (domains int, ips int) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.forward), len(t.reverse)
}

// ipsetFor returns the appropriate ipset for the given IP address.
func (t *Tracker) ipsetFor(ip string) *netfilter.IPSet {
	if isIPv6(ip) && t.ipset6 != nil {
		return t.ipset6
	}
	return t.ipset4
}

// isIPv6 reports whether the given IP string is an IPv6 address.
func isIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}
