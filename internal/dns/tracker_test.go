package dns

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"testing"
)

// fakeIPSet is an in-memory ipset recording every exec the tracker makes.
type fakeIPSet struct {
	mu      sync.Mutex
	members map[string]struct{}
	calls   []string // "add 1.2.3.4", "del ...", "flush", "list"
	failAdd map[string]bool
}

func newFakeIPSet() *fakeIPSet {
	return &fakeIPSet{members: map[string]struct{}{}, failAdd: map[string]bool{}}
}

func (f *fakeIPSet) Add(_ context.Context, e string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "add "+e)
	if f.failAdd[e] {
		return errors.New("add failed")
	}
	f.members[e] = struct{}{}
	return nil
}

func (f *fakeIPSet) Del(_ context.Context, e string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "del "+e)
	delete(f.members, e)
	return nil
}

func (f *fakeIPSet) Flush(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "flush")
	f.members = map[string]struct{}{}
	return nil
}

func (f *fakeIPSet) List(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "list")
	out := make([]string, 0, len(f.members))
	for m := range f.members {
		out = append(out, m)
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeIPSet) count(call string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == call {
			n++
		}
	}
	return n
}

func (f *fakeIPSet) has(m string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.members[m]
	return ok
}

func (f *fakeIPSet) set(members ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.members = map[string]struct{}{}
	for _, m := range members {
		f.members[m] = struct{}{}
	}
}

// conntrackLog records conntrack flushes instead of exec'ing conntrack.
type conntrackLog struct {
	mu      sync.Mutex
	flushed []string
}

func (c *conntrackLog) flush(_ context.Context, m string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flushed = append(c.flushed, m)
}

func (c *conntrackLog) count(m string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, f := range c.flushed {
		if f == m {
			n++
		}
	}
	return n
}

func newTestTracker() (*Tracker, *fakeIPSet, *conntrackLog) {
	fs := newFakeIPSet()
	ct := &conntrackLog{}
	tr := NewTracker(fs, slog.New(slog.NewTextHandler(io.Discard, nil)))
	tr.flushConntrack = ct.flush
	return tr, fs, ct
}

func TestTrackerTrackAndCount(t *testing.T) {
	tr, _, _ := newTestTracker()
	ctx := context.Background()

	tr.Track(ctx, "example.com", "1.2.3.4")
	tr.Track(ctx, "example.com", "1.2.3.5")
	tr.Track(ctx, "other.com", "1.2.3.4") // shared IP

	domains, ips := tr.Count()
	if domains != 2 {
		t.Errorf("domains = %d, want 2", domains)
	}
	if ips != 2 {
		t.Errorf("ips = %d, want 2", ips)
	}
}

func TestTrackerTrackNoDuplicates(t *testing.T) {
	tr, _, _ := newTestTracker()
	ctx := context.Background()

	tr.Track(ctx, "example.com", "1.2.3.4")
	tr.Track(ctx, "example.com", "1.2.3.4")
	tr.Track(ctx, "example.com", "1.2.3.4")

	domains, ips := tr.Count()
	if domains != 1 || ips != 1 {
		t.Errorf("after duplicate tracks: domains=%d, ips=%d, want 1,1", domains, ips)
	}
}

func TestTrackerRepeatedTrackExecsAddOnce(t *testing.T) {
	tr, fs, ct := newTestTracker()
	ctx := context.Background()

	for range 5 {
		tr.Track(ctx, "example.com", "1.2.3.4")
	}
	tr.Track(ctx, "other.com", "1.2.3.4") // shared IP, already present

	if n := fs.count("add 1.2.3.4"); n != 1 {
		t.Errorf("ipset add execs = %d, want 1", n)
	}
	if n := ct.count("1.2.3.4"); n != 1 {
		t.Errorf("conntrack flushes = %d, want 1", n)
	}
	if !fs.has("1.2.3.4") {
		t.Error("1.2.3.4 not in ipset")
	}
}

func TestTrackerFailedAddLeavesMapsAndRetries(t *testing.T) {
	tr, fs, ct := newTestTracker()
	ctx := context.Background()

	fs.failAdd["1.2.3.4"] = true
	tr.Track(ctx, "example.com", "1.2.3.4")

	if d, ips := tr.Count(); d != 0 || ips != 0 {
		t.Fatalf("after failed add: domains=%d ips=%d, want 0,0", d, ips)
	}
	if n := ct.count("1.2.3.4"); n != 0 {
		t.Errorf("conntrack flushed %d times after failed add, want 0", n)
	}

	fs.failAdd["1.2.3.4"] = false
	tr.Track(ctx, "example.com", "1.2.3.4")

	if d, ips := tr.Count(); d != 1 || ips != 1 {
		t.Errorf("after retry: domains=%d ips=%d, want 1,1", d, ips)
	}
	if n := fs.count("add 1.2.3.4"); n != 2 {
		t.Errorf("ipset add execs = %d, want 2 (fail + retry)", n)
	}
	if !fs.has("1.2.3.4") {
		t.Error("1.2.3.4 not in ipset after retry")
	}
	if n := ct.count("1.2.3.4"); n != 1 {
		t.Errorf("conntrack flushes = %d, want 1", n)
	}
}

func TestTrackerRemoveDomain(t *testing.T) {
	tr, fs, _ := newTestTracker()
	ctx := context.Background()

	tr.Track(ctx, "example.com", "1.2.3.4")
	tr.Track(ctx, "other.com", "1.2.3.4")

	// Remove example.com: IP still referenced by other.com.
	tr.RemoveDomain(ctx, "example.com")

	domains, ips := tr.Count()
	if domains != 1 || ips != 1 {
		t.Errorf("domains=%d ips=%d, want 1,1 (still referenced by other.com)", domains, ips)
	}
	if !fs.has("1.2.3.4") {
		t.Error("1.2.3.4 left the ipset while other.com holds it")
	}

	// Remove other.com: IP now unreferenced.
	tr.RemoveDomain(ctx, "other.com")

	domains, ips = tr.Count()
	if domains != 0 || ips != 0 {
		t.Errorf("domains=%d ips=%d, want 0,0", domains, ips)
	}
	if fs.has("1.2.3.4") {
		t.Error("1.2.3.4 still in ipset with no references")
	}
}

func TestTrackerStaticAndDomainShareIP(t *testing.T) {
	ctx := context.Background()

	t.Run("static removed first", func(t *testing.T) {
		tr, fs, ct := newTestTracker()
		tr.Track(ctx, "example.com", "1.2.3.4")
		tr.SetStatic(ctx, []string{"1.2.3.4/32"}) // canonicalised to 1.2.3.4

		if n := fs.count("add 1.2.3.4"); n != 1 {
			t.Errorf("ipset add execs = %d, want 1", n)
		}
		tr.SetStatic(ctx, nil)
		if !fs.has("1.2.3.4") {
			t.Fatal("static removal yanked an IP a domain still holds")
		}
		if n := fs.count("del 1.2.3.4"); n != 0 {
			t.Errorf("ipset del execs = %d, want 0", n)
		}
		tr.RemoveDomain(ctx, "example.com")
		if fs.has("1.2.3.4") {
			t.Error("IP still in ipset after last reference went")
		}
		// Flushed once on add, once on final removal.
		if n := ct.count("1.2.3.4"); n != 2 {
			t.Errorf("conntrack flushes = %d, want 2", n)
		}
	})

	t.Run("domain removed first", func(t *testing.T) {
		tr, fs, _ := newTestTracker()
		tr.SetStatic(ctx, []string{"1.2.3.4"})
		tr.Track(ctx, "example.com", "1.2.3.4")

		if n := fs.count("add 1.2.3.4"); n != 1 {
			t.Errorf("ipset add execs = %d, want 1", n)
		}
		tr.RemoveDomain(ctx, "example.com")
		if !fs.has("1.2.3.4") {
			t.Fatal("domain removal yanked a static entry")
		}
		if d, ips := tr.Count(); d != 0 || ips != 0 {
			t.Errorf("Count = %d,%d, want 0,0 (static not counted)", d, ips)
		}
		tr.SetStatic(ctx, nil)
		if fs.has("1.2.3.4") {
			t.Error("IP still in ipset after last reference went")
		}
	})

	t.Run("cidr static flushes conntrack on add and remove", func(t *testing.T) {
		tr, fs, ct := newTestTracker()
		tr.SetStatic(ctx, []string{"10.1.2.3/16"})
		if !fs.has("10.1.0.0/16") {
			t.Fatal("CIDR not added in canonical form")
		}
		tr.SetStatic(ctx, []string{"10.1.0.0/16"}) // same member, no-op
		if n := fs.count("add 10.1.0.0/16"); n != 1 {
			t.Errorf("ipset add execs = %d, want 1", n)
		}
		tr.SetStatic(ctx, nil)
		if fs.has("10.1.0.0/16") {
			t.Error("CIDR still in ipset")
		}
		if n := ct.count("10.1.0.0/16"); n != 2 {
			t.Errorf("conntrack flushes = %d, want 2", n)
		}
	})

	t.Run("failed static add retries on next SetStatic", func(t *testing.T) {
		tr, fs, _ := newTestTracker()
		fs.failAdd["5.5.5.5"] = true
		tr.SetStatic(ctx, []string{"5.5.5.5"})
		fs.failAdd["5.5.5.5"] = false
		tr.SetStatic(ctx, []string{"5.5.5.5"})
		if !fs.has("5.5.5.5") {
			t.Error("static entry not retried")
		}
	})
}

func TestTrackerRepair(t *testing.T) {
	tr, fs, ct := newTestTracker()
	ctx := context.Background()

	tr.Track(ctx, "example.com", "1.2.3.4")
	tr.Track(ctx, "example.com", "1.2.3.5")
	tr.SetStatic(ctx, []string{"10.0.0.0/8"})

	// External interference: one tracked IP and the CIDR vanish, a bogus
	// member appears.
	fs.set("1.2.3.5", "203.0.113.7")

	added, removed, err := tr.Repair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if added != 2 || removed != 1 {
		t.Errorf("Repair = +%d -%d, want +2 -1", added, removed)
	}
	if n := fs.count("list"); n != 1 {
		t.Errorf("ipset list execs = %d, want 1", n)
	}
	got, _ := fs.List(ctx)
	want := []string{"1.2.3.4", "1.2.3.5", "10.0.0.0/8"}
	if !slices.Equal(got, want) {
		t.Errorf("ipset after repair = %v, want %v", got, want)
	}
	if ct.count("203.0.113.7") != 1 || ct.count("1.2.3.4") != 2 {
		t.Errorf("conntrack flushes = %v", ct.flushed)
	}

	// In sync now: second repair changes nothing.
	added, removed, err = tr.Repair(ctx)
	if err != nil || added != 0 || removed != 0 {
		t.Errorf("second Repair = +%d -%d err=%v, want no-op", added, removed, err)
	}
}

func TestTrackerRepairForgetsUnaddable(t *testing.T) {
	tr, fs, _ := newTestTracker()
	ctx := context.Background()

	tr.Track(ctx, "example.com", "1.2.3.4")
	fs.set()
	fs.failAdd["1.2.3.4"] = true

	if _, _, err := tr.Repair(ctx); err != nil {
		t.Fatal(err)
	}
	if d, ips := tr.Count(); d != 0 || ips != 0 {
		t.Errorf("Count = %d,%d, want 0,0: maps must match the kernel", d, ips)
	}
}

func TestDiffMembers(t *testing.T) {
	known := map[string]struct{}{"1.1.1.1": {}, "10.0.0.0/8": {}, "2.2.2.2": {}}
	kernel := []string{"1.1.1.1", "10.0.0.0/8", "9.9.9.9", "192.168.0.0/16"}
	missing, unknown := diffMembers(known, kernel)
	if !slices.Equal(missing, []string{"2.2.2.2"}) {
		t.Errorf("missing = %v", missing)
	}
	if !slices.Equal(unknown, []string{"192.168.0.0/16", "9.9.9.9"}) {
		t.Errorf("unknown = %v", unknown)
	}
}

func TestCanonicalMember(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":     "1.2.3.4",
		"1.2.3.4/32":  "1.2.3.4",
		"10.1.2.3/16": "10.1.0.0/16",
		"10.0.0.0/8":  "10.0.0.0/8",
	}
	for in, want := range cases {
		got, ok := canonicalMember(in)
		if !ok || got != want {
			t.Errorf("canonicalMember(%q) = %q,%v, want %q", in, got, ok, want)
		}
	}
	if _, ok := canonicalMember("nope"); ok {
		t.Error("canonicalMember accepted garbage")
	}
}

func TestTrackerConcurrentTrackRemove(t *testing.T) {
	tr, fs, _ := newTestTracker()
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			tr.Track(ctx, "a.com", "1.2.3.4")
		}()
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				tr.RemoveDomain(ctx, "a.com")
			} else {
				tr.Track(ctx, "b.com", "1.2.3.4")
			}
		}()
	}
	wg.Wait()

	_, ips := tr.Count()
	if (ips == 1) != fs.has("1.2.3.4") {
		t.Errorf("maps (ips=%d) disagree with kernel (has=%v)", ips, fs.has("1.2.3.4"))
	}
}

func TestTrackerFlush(t *testing.T) {
	tr, fs, _ := newTestTracker()
	ctx := context.Background()

	tr.Track(ctx, "a.com", "1.1.1.1")
	tr.Track(ctx, "b.com", "2.2.2.2")
	tr.SetStatic(ctx, []string{"3.3.3.3"})
	if err := tr.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	domains, ips := tr.Count()
	if domains != 0 || ips != 0 {
		t.Errorf("after flush: domains=%d, ips=%d, want 0,0", domains, ips)
	}
	// Static entries are forgotten too: the next SetStatic re-adds them.
	tr.SetStatic(ctx, []string{"3.3.3.3"})
	if !fs.has("3.3.3.3") {
		t.Error("static entry not re-added after flush")
	}
}
