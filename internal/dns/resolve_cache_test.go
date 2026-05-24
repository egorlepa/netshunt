package dns

import (
	"sync"
	"testing"
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
