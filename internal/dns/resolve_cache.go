package dns

import (
	"container/list"
	"sync"
)

// ResolveCache remembers the most recent successful A-record resolutions
// (domain → IPs) seen by the forwarder. Bounded LRU, no TTL.
//
// Purpose: when a shunt rule is added, the cache lets the reconciler
// retroactively populate the kernel ipset for IPs the client already cached.
// Without this, clients with a warm DNS cache continue routing the cached IP
// past iptables until their cache entry expires.
type ResolveCache struct {
	mu    sync.Mutex
	cap   int
	order *list.List // values are *resolveEntry; front = most recent
	by    map[string]*list.Element
}

type resolveEntry struct {
	domain string
	ips    []string
}

// NewResolveCache returns an empty cache with the given entry capacity.
func NewResolveCache(capacity int) *ResolveCache {
	return &ResolveCache{
		cap:   capacity,
		order: list.New(),
		by:    make(map[string]*list.Element, capacity),
	}
}

// Remember inserts or refreshes the entry for domain. ips is copied; the
// caller may mutate or reuse the slice afterwards. Empty ips is a no-op.
func (c *ResolveCache) Remember(domain string, ips []string) {
	if domain == "" || len(ips) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.by[domain]; ok {
		e := el.Value.(*resolveEntry)
		e.ips = append(e.ips[:0], ips...)
		c.order.MoveToFront(el)
		return
	}

	e := &resolveEntry{
		domain: domain,
		ips:    append(make([]string, 0, len(ips)), ips...),
	}
	c.by[domain] = c.order.PushFront(e)

	for c.order.Len() > c.cap {
		back := c.order.Back()
		if back == nil {
			break
		}
		c.order.Remove(back)
		delete(c.by, back.Value.(*resolveEntry).domain)
	}
}

// Range walks every cached (domain, ips) entry in unspecified order. The
// callback returning false stops iteration. The cache lock is held for the
// entire call — callers must not Remember from inside fn.
//
// The ips slice passed to fn aliases internal storage; do not mutate or
// retain it beyond the call.
func (c *ResolveCache) Range(fn func(domain string, ips []string) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for el := c.order.Front(); el != nil; el = el.Next() {
		e := el.Value.(*resolveEntry)
		if !fn(e.domain, e.ips) {
			return
		}
	}
}

// Len returns the current number of cached entries.
func (c *ResolveCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
