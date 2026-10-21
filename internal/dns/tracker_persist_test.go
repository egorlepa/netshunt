package dns

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/egorlepa/netshunt/internal/shunt"
)

func persistedTracker(t *testing.T, path string, interval time.Duration) (*Tracker, *fakeIPSet, *conntrackLog) {
	t.Helper()
	tr, fs, ct := newTestTracker()
	tr.EnablePersistence(path, interval)
	return tr, fs, ct
}

func readTrackerFile(t *testing.T, path string) trackerFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f trackerFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse %s: %v\n%s", path, err, data)
	}
	return f
}

func matchAll(string) bool { return true }

func TestTrackerPersistRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "tracker.json")
	a, _, _ := persistedTracker(t, path, time.Hour)
	ctx := context.Background()
	a.Track(ctx, "www.example.net", "198.51.100.1")
	a.Track(ctx, "www.example.net", "198.51.100.2")
	a.Track(ctx, "api.example.net", "198.51.100.2")
	a.SetStatic(ctx, []string{"203.0.113.0/24"})
	if err := a.Save(); err != nil {
		t.Fatal(err)
	}
	f := readTrackerFile(t, path)
	if f.Version != 1 || len(f.Domains) != 2 || !slices.Equal(f.Domains["www.example.net"], []string{"198.51.100.1", "198.51.100.2"}) {
		t.Fatalf("file = %+v", f)
	}
	if _, ok := f.Domains["203.0.113.0/24"]; ok {
		t.Fatal("static entry persisted")
	}

	b, bfs, bct := persistedTracker(t, path, time.Hour)
	res, err := b.LoadPersisted(matchAll)
	if err != nil {
		t.Fatal(err)
	}
	if res != (LoadResult{Domains: 2, IPs: 2}) {
		t.Fatalf("load = %+v", res)
	}
	if d, ips := b.Count(); d != 2 || ips != 2 {
		t.Fatalf("count = %d/%d", d, ips)
	}
	if len(bfs.calls) != 0 || len(bct.flushed) != 0 {
		t.Fatalf("load exec'd: ipset %v conntrack %v", bfs.calls, bct.flushed)
	}
	// Loaded members are believed present: tracking them again execs nothing.
	b.Track(ctx, "www.example.net", "198.51.100.1")
	if len(bfs.calls) != 0 {
		t.Fatalf("re-track of a loaded IP exec'd: %v", bfs.calls)
	}
}

func TestTrackerPersistAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tracker.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"domains":{"old.example":["192.0.2.1"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, _, _ := persistedTracker(t, path, time.Hour)
	tr.Track(context.Background(), "new.example", "192.0.2.2")
	if err := tr.Save(); err != nil {
		t.Fatal(err)
	}
	f := readTrackerFile(t, path)
	if _, ok := f.Domains["old.example"]; ok || len(f.Domains) != 1 {
		t.Fatalf("file not replaced: %+v", f)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.Name() != "tracker.json" {
			t.Errorf("leftover file %s", e.Name())
		}
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v", st.Mode())
	}
}

func TestTrackerPersistDebounced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tracker.json")
	tr, _, _ := persistedTracker(t, path, 150*time.Millisecond)
	ctx := context.Background()
	tr.Track(ctx, "a.example", "192.0.2.1")
	tr.Track(ctx, "b.example", "192.0.2.2")
	tr.Track(ctx, "a.example", "192.0.2.1") // no change, no write
	if _, err := os.Stat(path); err == nil {
		t.Fatal("written before the debounce interval")
	}
	deadline := time.Now().Add(2 * time.Second)
	for tr.persist.writes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if n := tr.persist.writes.Load(); n != 1 {
		t.Fatalf("%d writes for two quick changes, want 1", n)
	}
	if f := readTrackerFile(t, path); len(f.Domains) != 2 {
		t.Fatalf("file = %+v", f)
	}

	// A removal is a change too.
	tr.RemoveDomain(ctx, "a.example")
	deadline = time.Now().Add(2 * time.Second)
	for tr.persist.writes.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if f := readTrackerFile(t, path); len(f.Domains) != 1 {
		t.Fatalf("after removal file = %+v", f)
	}

	// Save cancels a pending write and writes at once.
	tr.Track(ctx, "c.example", "192.0.2.3")
	if err := tr.Save(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if n := tr.persist.writes.Load(); n != 3 {
		t.Fatalf("writes = %d, want 3 (the pending one was cancelled)", n)
	}
}

func TestTrackerLoadCorruptOrMissingIsEmpty(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"garbage": "{not json",
		"version": `{"version":2,"domains":{"a.example":["192.0.2.1"]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".json")
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			tr, _, _ := persistedTracker(t, path, time.Hour)
			if _, err := tr.LoadPersisted(matchAll); err == nil {
				t.Fatal("no error for a bad file")
			}
			if d, ips := tr.Count(); d != 0 || ips != 0 {
				t.Fatalf("count = %d/%d", d, ips)
			}
		})
	}
	tr, _, _ := persistedTracker(t, filepath.Join(dir, "missing.json"), time.Hour)
	if res, err := tr.LoadPersisted(matchAll); err != nil || res != (LoadResult{}) {
		t.Fatalf("missing file: %+v, %v", res, err)
	}
}

func TestTrackerLoadFilteredThroughMatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tracker.json")
	content := `{"version":1,"domains":{
		"www.example.net":["198.51.100.1"],
		"shared.example.net":["198.51.100.9"],
		"gone.org":["198.51.100.9","198.51.100.3"],
		"bad.example.net":["not-an-ip"]}}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewMatcher()
	m.Update([]shunt.Entry{{Value: "example.net"}})
	tr, _, _ := persistedTracker(t, path, time.Hour)
	res, err := tr.LoadPersisted(m.Match)
	if err != nil {
		t.Fatal(err)
	}
	if res != (LoadResult{Domains: 2, IPs: 2, Dropped: 1}) {
		t.Fatalf("load = %+v", res)
	}
	got := tr.Domains()
	slices.Sort(got)
	if !slices.Equal(got, []string{"shared.example.net", "www.example.net"}) {
		t.Fatalf("domains = %v", got)
	}
}

func TestTrackerRepairAfterLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tracker.json")
	content := `{"version":1,"domains":{"a.example":["192.0.2.1"],"b.example":["192.0.2.2"]}}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, fs, ct := persistedTracker(t, path, time.Hour)
	// Kernel after a daemon restart: a.example's IP present, b.example's
	// missing, one member nothing explains.
	fs.set("192.0.2.1", "203.0.113.50")
	if _, err := tr.LoadPersisted(matchAll); err != nil {
		t.Fatal(err)
	}
	tr.PresumeStatic([]string{"198.51.100.0/24"})
	added, removed, err := tr.Repair(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if added != 2 || removed != 1 {
		t.Fatalf("repair added %d removed %d", added, removed)
	}
	kernel, _ := fs.List(context.Background())
	if want := []string{"192.0.2.1", "192.0.2.2", "198.51.100.0/24"}; !slices.Equal(kernel, want) {
		t.Fatalf("kernel = %v, want %v", kernel, want)
	}
	if fs.count("flush") != 0 || fs.count("add 192.0.2.1") != 0 {
		t.Fatalf("calls = %v", fs.calls)
	}
	// Conntrack is flushed only for members whose kernel state changed.
	if ct.count("192.0.2.1") != 0 || ct.count("192.0.2.2") != 1 || ct.count("203.0.113.50") != 1 {
		t.Fatalf("conntrack = %v", ct.flushed)
	}
	if strings.Join(tr.Domains(), ",") == "" {
		t.Fatal("domains lost")
	}
}
