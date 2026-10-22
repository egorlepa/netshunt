package daemon

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egorlepa/netshunt/internal/blocklist"
	"github.com/egorlepa/netshunt/internal/config"
)

// blocklistHarness wires a blocklist store with hagezi-light (default on)
// into the reconciler and captures its log to count rebuilds.
type blocklistHarness struct {
	*harness
	bl   *blocklist.Store
	logs *strings.Builder
}

func newBlocklistHarness(t *testing.T) *blocklistHarness {
	t.Helper()
	h := newHarness(t)
	dir := t.TempDir()
	bl, err := blocklist.NewStore(filepath.Join(dir, "blocklist.yaml"), filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bl.CacheDir(), 0755); err != nil {
		t.Fatal(err)
	}
	h.r.Blocklist = bl
	logs := &strings.Builder{}
	h.r.Logger = slog.New(slog.NewTextHandler(&lockedWriter{w: logs}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := config.Defaults()
	cfg.Blocklist.Enabled = true
	h.r.Config.Store(&cfg)
	return &blocklistHarness{harness: h, bl: bl, logs: logs}
}

// writeCache writes a source's cache file with a fixed mtime.
func (h *blocklistHarness) writeCache(id, content string, mtime time.Time) {
	h.t.Helper()
	path := blocklist.CachePath(h.bl.CacheDir(), id)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		h.t.Fatal(err)
	}
}

func (h *blocklistHarness) apply() {
	h.t.Helper()
	if err := h.r.ApplyBlocklist(context.Background()); err != nil {
		h.t.Fatal(err)
	}
}

// builds counts the matcher rebuilds (enabled builds and clears) so far.
func (h *blocklistHarness) builds() int {
	s := h.logs.String()
	return strings.Count(s, `msg="blocklist applied"`) + strings.Count(s, `msg="blocklist cleared"`)
}

func (h *blocklistHarness) wantBuilds(n int) {
	h.t.Helper()
	if got := h.builds(); got != n {
		h.t.Fatalf("builds = %d, want %d\n%s", got, n, h.logs.String())
	}
}

func (h *blocklistHarness) blocked(domain string) bool {
	return h.fwd.Blocklist().Match(domain)
}

var blMtime = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func TestBlocklistRebuildOnlyWhenInputsChange(t *testing.T) {
	h := newBlocklistHarness(t)
	h.writeCache("hagezi-light", "ads.example.com\n", blMtime)

	h.apply()
	h.wantBuilds(1)
	if !h.blocked("x.ads.example.com") {
		t.Fatal("not blocked after first apply")
	}

	// Unchanged inputs: no rebuild, also through a full reconcile. The file
	// is rewritten with other content of the same size and mtime, which a
	// rebuild would pick up: the old rules staying proves none ran.
	h.writeCache("hagezi-light", "bds.example.com\n", blMtime)
	h.apply()
	h.reconcile()
	h.wantBuilds(1)
	if !h.blocked("ads.example.com") || h.blocked("bds.example.com") {
		t.Fatal("matcher rebuilt with unchanged fingerprint")
	}
	if !strings.Contains(h.logs.String(), "blocklist unchanged") {
		t.Fatal("no debug line for the skipped rebuild")
	}

	// Response kind change: no rebuild (SetBlockResponse runs before the check).
	cfg := *h.r.Config.Load()
	cfg.Blocklist.Response = config.BlocklistResponseZero
	h.r.Config.Store(&cfg)
	h.apply()
	h.wantBuilds(1)

	// Touched cache file (new mtime): rebuild.
	h.writeCache("hagezi-light", "bds.example.com\n", blMtime.Add(time.Second))
	h.apply()
	h.wantBuilds(2)
	if h.blocked("ads.example.com") || !h.blocked("bds.example.com") {
		t.Fatal("new file content not applied")
	}

	// Same mtime, different size: rebuild.
	h.writeCache("hagezi-light", "cdns.example.com\n", blMtime.Add(time.Second))
	h.apply()
	h.wantBuilds(3)
	if !h.blocked("cdns.example.com") {
		t.Fatal("size change not applied")
	}

	// Toggling a source: rebuild.
	h.writeCache("hagezi-pro", "pro.example.net\n", blMtime)
	h.do(h.bl.SetEnabled("hagezi-pro", true))
	h.apply()
	h.wantBuilds(4)
	if !h.blocked("pro.example.net") {
		t.Fatal("enabled source not applied")
	}
	h.do(h.bl.SetEnabled("hagezi-pro", false))
	h.apply()
	h.wantBuilds(5)
	if h.blocked("pro.example.net") {
		t.Fatal("disabled source still applied")
	}
}

func TestBlocklistDisabledClearsOnce(t *testing.T) {
	h := newBlocklistHarness(t)
	h.writeCache("hagezi-light", "ads.example.com\n", blMtime)
	h.apply()
	h.wantBuilds(1)

	cfg := *h.r.Config.Load()
	cfg.Blocklist.Enabled = false
	h.r.Config.Store(&cfg)
	h.apply()
	h.apply()
	h.reconcile()
	h.wantBuilds(2)
	if h.blocked("ads.example.com") || h.fwd.Blocklist().Len() != 0 {
		t.Fatal("disabled blocklist still blocks")
	}

	cfg.Blocklist.Enabled = true
	h.r.Config.Store(&cfg)
	h.apply()
	h.wantBuilds(3)
	if !h.blocked("ads.example.com") {
		t.Fatal("re-enabled blocklist does not block")
	}
}

func TestBlocklistMissingSourceWarned(t *testing.T) {
	h := newBlocklistHarness(t)
	h.apply() // hagezi-light enabled, never downloaded
	if !strings.Contains(h.logs.String(), `msg="blocklist source unreadable" id=hagezi-light`) {
		t.Fatalf("missing cache file not warned:\n%s", h.logs.String())
	}
	// The download appearing is a fingerprint change.
	h.writeCache("hagezi-light", "ads.example.com\n", blMtime)
	h.apply()
	h.wantBuilds(2)
	if !h.blocked("ads.example.com") {
		t.Fatal("downloaded source not applied")
	}
}
