package dns

import (
	"container/list"
	"slices"
	"sync"
	"time"
)

// maxSeedIPs caps the accumulated A-record IPs kept per domain.
const maxSeedIPs = 16

// maxCachedResponse skips caching unusually large responses so one domain
// cannot pin a big buffer in router memory.
const maxCachedResponse = 4096

// ResolveCache is the forwarder's per-domain memory, a bounded LRU keyed by
// lowercase domain name. Each entry holds two things:
//
//   - Seeding IPs: every A-record address seen for the domain, accumulated
//     across responses (newest last, at most maxSeedIPs, oldest dropped).
//     They never expire except by LRU eviction. When a shunt rule is added,
//     the reconciler ranges over them to retroactively populate the kernel
//     ipset for IPs clients already cached. Without this, clients with a
//     warm DNS cache keep routing the cached IP past iptables until their
//     cache entry expires. The forwarder remembers an answer's IPs under
//     every name of its CNAME chain, so each alias is an entry of its own
//     and counts against the capacity like any other.
//   - Response cache: per query type, the packed upstream response and its
//     expiry, answering repeat queries without an upstream round trip.
type ResolveCache struct {
	mu    sync.Mutex
	cap   int
	now   func() time.Time
	order *list.List // values are *resolveEntry; front = most recent
	by    map[string]*list.Element
}

type resolveEntry struct {
	domain string
	ips    []string
	resps  []cachedResponse // few entries (A, HTTPS, ...), linear scan
}

type cachedResponse struct {
	qtype    uint16
	packed   []byte
	storedAt time.Time
	expires  time.Time
}

// NewResolveCache returns an empty cache with the given entry capacity.
func NewResolveCache(capacity int) *ResolveCache {
	return &ResolveCache{
		cap:   capacity,
		now:   time.Now,
		order: list.New(),
		by:    make(map[string]*list.Element, capacity),
	}
}

// entryLocked returns domain's entry moved to the front, creating it (and
// evicting the LRU tail) when missing.
func (c *ResolveCache) entryLocked(domain string) *resolveEntry {
	if el, ok := c.by[domain]; ok {
		c.order.MoveToFront(el)
		return el.Value.(*resolveEntry)
	}
	e := &resolveEntry{domain: domain}
	c.by[domain] = c.order.PushFront(e)
	for c.order.Len() > c.cap {
		back := c.order.Back()
		if back == nil {
			break
		}
		c.order.Remove(back)
		delete(c.by, back.Value.(*resolveEntry).domain)
	}
	return e
}

// Remember adds ips to domain's accumulated seeding IPs. An IP already
// present moves to the newest position; beyond maxSeedIPs the oldest are
// dropped. ips is copied. Empty ips is a no-op.
func (c *ResolveCache) Remember(domain string, ips []string) {
	if domain == "" || len(ips) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	e := c.entryLocked(domain)
	for _, ip := range ips {
		if i := slices.Index(e.ips, ip); i >= 0 {
			e.ips = append(e.ips[:i], e.ips[i+1:]...)
		}
		e.ips = append(e.ips, ip)
	}
	if n := len(e.ips) - maxSeedIPs; n > 0 {
		e.ips = append(e.ips[:0], e.ips[n:]...)
	}
}

// StoreResponse caches packed (copied) as domain's response for qtype for
// ttl. A non-positive ttl or an oversized message is ignored.
func (c *ResolveCache) StoreResponse(domain string, qtype uint16, packed []byte, ttl time.Duration) {
	if domain == "" || ttl <= 0 || len(packed) == 0 || len(packed) > maxCachedResponse {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	r := cachedResponse{
		qtype:    qtype,
		packed:   slices.Clone(packed),
		storedAt: now,
		expires:  now.Add(ttl),
	}
	e := c.entryLocked(domain)
	for i := range e.resps {
		if e.resps[i].qtype == qtype {
			e.resps[i] = r
			return
		}
	}
	e.resps = append(e.resps, r)
}

// LookupResponse returns a copy of the live cached response for (domain,
// qtype) and how long ago it was stored. An expired response is dropped.
func (c *ResolveCache) LookupResponse(domain string, qtype uint16) (packed []byte, age time.Duration, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, found := c.by[domain]
	if !found {
		return nil, 0, false
	}
	e := el.Value.(*resolveEntry)
	for i := range e.resps {
		r := &e.resps[i]
		if r.qtype != qtype {
			continue
		}
		now := c.now()
		if !now.Before(r.expires) {
			e.resps = slices.Delete(e.resps, i, i+1)
			if len(e.resps) == 0 && len(e.ips) == 0 {
				c.order.Remove(el)
				delete(c.by, domain)
			}
			return nil, 0, false
		}
		c.order.MoveToFront(el)
		return slices.Clone(r.packed), now.Sub(r.storedAt), true
	}
	return nil, 0, false
}

// Range walks every domain that has accumulated seeding IPs, in unspecified
// order. Domains with only cached responses are skipped. The callback
// returning false stops iteration. The cache lock is held for the entire
// call; callers must not call other cache methods from inside fn.
//
// The ips slice passed to fn aliases internal storage; do not mutate or
// retain it beyond the call.
func (c *ResolveCache) Range(fn func(domain string, ips []string) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for el := c.order.Front(); el != nil; el = el.Next() {
		e := el.Value.(*resolveEntry)
		if len(e.ips) == 0 {
			continue
		}
		if !fn(e.domain, e.ips) {
			return
		}
	}
}

// Len returns the current number of cached domains.
func (c *ResolveCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// Cap returns the entry capacity.
func (c *ResolveCache) Cap() int {
	return c.cap
}
