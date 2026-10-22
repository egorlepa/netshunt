package daemon

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/egorlepa/netshunt/internal/shunt"
)

// persistHarness is a harness whose tracker persists to a temp file, as the
// daemon's does.
func persistHarness(t *testing.T) (*harness, string) {
	t.Helper()
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "lib", "tracker.json")
	h.fwd.TrackerRef().EnablePersistence(path, time.Hour)
	return h, path
}

// The cold Reconcile after a daemon restart: the kernel set still holds the
// previous daemon's members plus some nothing explains. It must end equal to
// the saved state filtered through the current rules, plus the static
// entries, without ever flushing the set.
func TestColdReconcileLoadsTrackerFileWithoutFlush(t *testing.T) {
	h, path := persistHarness(t)
	h.create("a", true, "example.net", "203.0.113.0/24")
	saved := `{"version":1,"domains":{
		"www.example.net":["198.51.100.1","198.51.100.2"],
		"api.example.net":["198.51.100.3"],
		"removed.org":["198.51.100.66"]}}`
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(saved), 0o644); err != nil {
		t.Fatal(err)
	}
	// Kernel: two of the saved IPs, the static CIDR, the IP of a domain no
	// rule matches any more, and an unknown member. api.example.net's IP is
	// missing (e.g. a manual del).
	for _, m := range []string{"198.51.100.1", "198.51.100.2", "203.0.113.0/24", "198.51.100.66", "192.0.2.77"} {
		h.ipset.members[m] = struct{}{}
	}

	h.reconcile()
	h.want("198.51.100.1", "198.51.100.2", "198.51.100.3", "203.0.113.0/24")
	if h.ipset.flushes != 0 {
		t.Fatalf("ipset flushed %d times", h.ipset.flushes)
	}
	got := h.fwd.TrackerRef().Domains()
	slices.Sort(got)
	if !slices.Equal(got, []string{"api.example.net", "www.example.net"}) {
		t.Fatalf("tracked domains = %v", got)
	}

	// Further reconciles and mutations never flush either.
	h.reconcile()
	h.mutate()
	if h.ipset.flushes != 0 {
		t.Fatalf("ipset flushed %d times", h.ipset.flushes)
	}
	h.want("198.51.100.1", "198.51.100.2", "198.51.100.3", "203.0.113.0/24")
}

// After a router reboot the kernel set is empty: Repair re-adds everything
// the file (filtered) and the shunts explain.
func TestColdReconcileAfterRebootRestoresFromFile(t *testing.T) {
	h, path := persistHarness(t)
	h.create("a", true, "example.net")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"domains":{"www.example.net":["198.51.100.1"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	h.reconcile()
	h.want("198.51.100.1")
}

func TestColdReconcileCorruptFileStartsEmpty(t *testing.T) {
	h, path := persistHarness(t)
	h.create("a", true, "example.net")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{truncated"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.ipset.members["198.51.100.1"] = struct{}{}
	h.reconcile()
	h.want() // nothing explains the kernel member
	if h.ipset.flushes != 0 {
		t.Fatal("flushed")
	}
}

func TestDaemonShutdownSavesTracker(t *testing.T) {
	h, path := persistHarness(t)
	h.create("a", true, "example.net")
	h.reconcile()
	h.resolve("www.example.net", "198.51.100.1")
	d := &Daemon{Forwarder: h.fwd, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	d.saveTracker()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Version int                 `json:"version"`
		Domains map[string][]string `json:"domains"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 || !slices.Equal(f.Domains["www.example.net"], []string{"198.51.100.1"}) {
		t.Fatalf("saved = %s", data)
	}

	// The next daemon loads it and keeps the member without re-adding it.
	h2 := newHarness(t)
	h2.fwd.TrackerRef().EnablePersistence(path, time.Hour)
	h2.create("a", true, "example.net")
	h2.ipset.members["198.51.100.1"] = struct{}{}
	h2.reconcile()
	h2.want("198.51.100.1")
	if d, _ := h2.fwd.TrackerRef().Count(); d != 1 {
		t.Fatalf("tracked domains = %d", d)
	}
}

func TestDaemonNormalizesGeositeShuntsOnce(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "shunts.yaml")
	old := "shunts:\n  - name: G\n    enabled: true\n    source: geosite:g\n    entries:\n      - value: domain:g.com\n      - value: domain:h.com\n"
	if err := os.WriteFile(path, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	d := &Daemon{Forwarder: h.fwd, Shunts: shunt.NewStore(path), Logger: slog.New(slog.NewTextHandler(&lockedWriter{w: &buf}, nil))}
	d.normalizeShunts()
	d.normalizeShunts()
	if n := strings.Count(buf.String(), "normalised 1 geosite shunts, dropped 2 copied entries"); n != 1 {
		t.Fatalf("log:\n%s", buf.String())
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "g.com") {
		t.Fatalf("file:\n%s", raw)
	}
}
