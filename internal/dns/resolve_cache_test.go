package dns

import (
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"
)

func collect(c *ResolveCache) map[string][]string {
	out := make(map[string][]string)
	c.Range(func(d string, ips []string) bool {
		cp := append([]string(nil), ips...)
		out[d] = cp
		return true
	})
	return out
}

func TestResolveCacheRememberAndRange(t *testing.T) {
	c := NewResolveCache(10)
	c.Remember("a.com", []string{"1.1.1.1", "1.1.1.2"})
	c.Remember("b.com", []string{"2.2.2.2"})

	if c.Len() != 2 {
		t.Fatalf("Len = %d, want 2", c.Len())
	}
	got := collect(c)
	if len(got["a.com"]) != 2 || got["a.com"][0] != "1.1.1.1" {
		t.Errorf("a.com = %v", got["a.com"])
	}
	if len(got["b.com"]) != 1 || got["b.com"][0] != "2.2.2.2" {
		t.Errorf("b.com = %v", got["b.com"])
	}
}

func TestResolveCacheCopiesIPs(t *testing.T) {
	c := NewResolveCache(10)
	ips := []string{"1.1.1.1"}
	c.Remember("a.com", ips)
	ips[0] = "9.9.9.9"

	got := collect(c)
	if got["a.com"][0] != "1.1.1.1" {
		t.Errorf("cache did not copy ips, got %v", got["a.com"])
	}
}

func TestResolveCacheLRUEviction(t *testing.T) {
	c := NewResolveCache(3)
	c.Remember("a.com", []string{"1"})
	c.Remember("b.com", []string{"2"})
	c.Remember("c.com", []string{"3"})
	c.Remember("d.com", []string{"4"}) // evicts a.com

	if c.Len() != 3 {
		t.Fatalf("Len = %d, want 3", c.Len())
	}
	got := collect(c)
	if _, ok := got["a.com"]; ok {
		t.Errorf("a.com should have been evicted")
	}
	for _, k := range []string{"b.com", "c.com", "d.com"} {
		if _, ok := got[k]; !ok {
			t.Errorf("%s missing from cache", k)
		}
	}
}

func TestResolveCacheRefreshMovesToFront(t *testing.T) {
	c := NewResolveCache(3)
	c.Remember("a.com", []string{"1"})
	c.Remember("b.com", []string{"2"})
	c.Remember("c.com", []string{"3"})
	// Touch a.com — it becomes most-recent, b.com is now LRU.
	c.Remember("a.com", []string{"1", "1b"})
	c.Remember("d.com", []string{"4"}) // should evict b.com, not a.com

	got := collect(c)
	if _, ok := got["b.com"]; ok {
		t.Errorf("b.com should have been evicted (LRU)")
	}
	if _, ok := got["a.com"]; !ok {
		t.Errorf("a.com should have survived (refreshed)")
	}
	if len(got["a.com"]) != 2 {
		t.Errorf("a.com ips = %v, want updated to 2 entries", got["a.com"])
	}
}

func TestResolveCacheEmptyInputsIgnored(t *testing.T) {
	c := NewResolveCache(10)
	c.Remember("", []string{"1.1.1.1"})
	c.Remember("a.com", nil)
	c.Remember("a.com", []string{})
	if c.Len() != 0 {
		t.Errorf("Len = %d, want 0", c.Len())
	}
}

func TestResolveCacheConcurrent(t *testing.T) {
	// Smoke-test for data races. Run with -race.
	c := NewResolveCache(100)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				c.Remember("d.com", []string{"1.1.1.1"})
				c.Range(func(string, []string) bool { return true })
			}
		}(w)
	}
	wg.Wait()
}

func TestResolveCacheAccumulatesIPs(t *testing.T) {
	c := NewResolveCache(10)
	c.Remember("a.com", []string{"1.1.1.1", "1.1.1.2"})
	c.Remember("a.com", []string{"1.1.1.3"})
	c.Remember("a.com", []string{"1.1.1.1"}) // re-seen: moves to newest

	want := []string{"1.1.1.2", "1.1.1.3", "1.1.1.1"}
	if got := collect(c)["a.com"]; !reflect.DeepEqual(got, want) {
		t.Errorf("a.com = %v, want %v", got, want)
	}
}

func TestResolveCacheIPCapDropsOldest(t *testing.T) {
	c := NewResolveCache(10)
	for i := range 20 {
		c.Remember("a.com", []string{fmt.Sprintf("10.0.0.%d", i)})
	}
	got := collect(c)["a.com"]
	if len(got) != maxSeedIPs {
		t.Fatalf("len = %d, want %d", len(got), maxSeedIPs)
	}
	if got[0] != "10.0.0.4" || got[len(got)-1] != "10.0.0.19" {
		t.Errorf("kept %v, want 10.0.0.4 .. 10.0.0.19", got)
	}
}

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time          { return f.t }
func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func newClockedCache(capacity int) (*ResolveCache, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := NewResolveCache(capacity)
	c.now = clk.now
	return c, clk
}

func TestResolveCacheResponseExpiry(t *testing.T) {
	c, clk := newClockedCache(10)
	c.StoreResponse("a.com", 1, []byte{1, 2, 3}, time.Minute)

	clk.advance(20 * time.Second)
	got, age, ok := c.LookupResponse("a.com", 1)
	if !ok || age != 20*time.Second || !reflect.DeepEqual(got, []byte{1, 2, 3}) {
		t.Fatalf("lookup = %v, %v, %v", got, age, ok)
	}
	got[0] = 9 // caller owns the copy
	if again, _, _ := c.LookupResponse("a.com", 1); again[0] != 1 {
		t.Errorf("lookup returned aliased storage")
	}
	if _, _, ok := c.LookupResponse("a.com", 28); ok {
		t.Errorf("other qtype should miss")
	}

	clk.advance(40 * time.Second)
	if _, _, ok := c.LookupResponse("a.com", 1); ok {
		t.Errorf("expired response served")
	}
	if c.Len() != 0 {
		t.Errorf("expired response-only entry kept, Len = %d", c.Len())
	}
}

func TestResolveCacheResponseKeepsSeedIPs(t *testing.T) {
	c, clk := newClockedCache(10)
	c.Remember("a.com", []string{"1.1.1.1"})
	c.StoreResponse("a.com", 1, []byte{1}, time.Minute)
	c.StoreResponse("b.com", 16, []byte{2}, time.Minute) // no IPs

	if got := collect(c); len(got) != 1 || got["a.com"][0] != "1.1.1.1" {
		t.Errorf("Range = %v, want only a.com", got)
	}
	clk.advance(2 * time.Minute)
	if _, _, ok := c.LookupResponse("a.com", 1); ok {
		t.Fatal("expired response served")
	}
	if got := collect(c)["a.com"]; len(got) != 1 {
		t.Errorf("seed IPs lost on response expiry: %v", got)
	}
}

func TestResolveCacheResponseIgnoresBadInput(t *testing.T) {
	c := NewResolveCache(10)
	c.StoreResponse("a.com", 1, []byte{1}, 0)
	c.StoreResponse("a.com", 1, nil, time.Minute)
	c.StoreResponse("a.com", 1, make([]byte, maxCachedResponse+1), time.Minute)
	if c.Len() != 0 {
		t.Errorf("Len = %d, want 0", c.Len())
	}
}

func TestResolveCacheLRUEvictionWithResponses(t *testing.T) {
	c := NewResolveCache(2)
	c.Remember("a.com", []string{"1.1.1.1"})
	c.StoreResponse("b.com", 1, []byte{2}, time.Minute)
	// A response hit on a.com makes it most recent, so b.com is the LRU.
	c.StoreResponse("a.com", 1, []byte{1}, time.Minute)
	if _, _, ok := c.LookupResponse("a.com", 1); !ok {
		t.Fatal("a.com miss")
	}
	c.Remember("c.com", []string{"3.3.3.3"})

	if _, _, ok := c.LookupResponse("b.com", 1); ok {
		t.Errorf("b.com should have been evicted")
	}
	got := collect(c)
	if len(got["a.com"]) != 1 || len(got["c.com"]) != 1 {
		t.Errorf("Range after eviction = %v", got)
	}
}

// TestResolveCacheAliasEntries covers what the forwarder does with a CNAME
// answer: the same IPs remembered under every chain name. Each alias
// accumulates on its own and is a full LRU entry.
func TestResolveCacheAliasEntries(t *testing.T) {
	c := NewResolveCache(3)
	chain := []string{"www.shop.com", "shop.cdn.cloudfront.net"}
	for _, name := range chain {
		c.Remember(name, []string{"13.32.10.5"})
	}
	// A later answer for the target alone (another site on the same CDN
	// name) accumulates there without touching the alias.
	c.Remember("shop.cdn.cloudfront.net", []string{"13.32.10.6"})
	got := collect(c)
	if !slices.Equal(got["www.shop.com"], []string{"13.32.10.5"}) ||
		!slices.Equal(got["shop.cdn.cloudfront.net"], []string{"13.32.10.5", "13.32.10.6"}) {
		t.Errorf("alias IPs = %v", got)
	}
	if c.Len() != 2 || c.Cap() != 3 {
		t.Errorf("Len/Cap = %d/%d, want 2/3", c.Len(), c.Cap())
	}

	// Two more names push the capacity: the oldest alias (www.shop.com) is
	// evicted like any entry.
	c.Remember("a.com", []string{"1.1.1.1"})
	c.Remember("b.com", []string{"2.2.2.2"})
	got = collect(c)
	if c.Len() != 3 {
		t.Errorf("Len = %d, want 3", c.Len())
	}
	if _, ok := got["www.shop.com"]; ok {
		t.Errorf("LRU alias not evicted: %v", got)
	}
	if _, ok := got["shop.cdn.cloudfront.net"]; !ok {
		t.Errorf("newer alias evicted: %v", got)
	}
}
