package web

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/geosite"
	"github.com/egorlepa/netshunt/internal/shunt"
)

// fakeGeosite is an in-memory geosite database.
type fakeGeosite struct {
	downloaded bool
	cats       map[string][]string // keyed by upper-case code, as in dlc.dat
}

func (f *fakeGeosite) FileInfo() geosite.FileInfo {
	if !f.downloaded {
		return geosite.FileInfo{}
	}
	return geosite.FileInfo{Downloaded: true, LastModified: time.Unix(1700000000, 0), CategoryCount: len(f.cats)}
}

func (f *fakeGeosite) Categories() ([]geosite.CategoryInfo, error) {
	var out []geosite.CategoryInfo
	for name, e := range f.cats {
		out = append(out, geosite.CategoryInfo{Name: name, DomainCount: len(e)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *fakeGeosite) Entries(category string) ([]string, bool) {
	if !f.downloaded {
		return nil, false
	}
	e, ok := f.cats[strings.ToUpper(category)]
	return e, ok
}

func newGeositeTestServer(t *testing.T) (*Server, *shunt.Store, *fakeGeosite, *countingReconciler, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shunts.yaml")
	store := shunt.NewStore(path)
	gs := &fakeGeosite{downloaded: true, cats: map[string][]string{
		"NETFLIX":    {"domain:netflix.com", "full:fast.com", "keyword:nflx", "regexp:(?<=x)y"},
		"DUCKDUCKGO": {"domain:duckduckgo.com"},
	}}
	store.SetGeositeProvider(gs)
	if err := store.Create(shunt.Shunt{Name: "manual", Enabled: true, Entries: []shunt.Entry{{Value: "inline.example.com"}}}); err != nil {
		t.Fatal(err)
	}
	rec := &countingReconciler{}
	cfg := config.Defaults()
	srv := NewServer(config.NewLive(&cfg), store, nil, gs, nil, rec, nil, nil, slog.New(slog.DiscardHandler), "test")
	return srv, store, gs, rec, path
}

func do(t *testing.T, s *Server, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestShuntsPageGeositeCardIsLazy(t *testing.T) {
	s, store, _, _, _ := newGeositeTestServer(t)
	if err := store.AddGeositeShunt("NETFLIX", "geosite:netflix"); err != nil {
		t.Fatal(err)
	}
	resp := do(t, s, http.MethodGet, "/shunts")
	body := resp.Body.String()
	if resp.Code != http.StatusOK {
		t.Fatalf("status %d", resp.Code)
	}
	// Manual shunt: entries inline, as before.
	if !strings.Contains(body, "inline.example.com") {
		t.Fatal("manual entries not inline")
	}
	// Geosite shunt: count from the database (3 valid of 4), entries not
	// inline, lazy endpoint wired.
	if strings.Contains(body, "netflix.com<") || strings.Contains(body, "fast.com") {
		t.Fatal("geosite entries rendered inline")
	}
	if !strings.Contains(body, "3 entries") || !strings.Contains(body, `hx-get="/shunts/NETFLIX/entries"`) ||
		!strings.Contains(body, "geosite:netflix") {
		t.Fatalf("geosite card:\n%s", body)
	}
	if strings.Contains(body, "not downloaded") || strings.Contains(body, "not in database") {
		t.Fatal("no-data badge on a shunt with data")
	}

	resp = do(t, s, http.MethodGet, "/shunts/NETFLIX/entries")
	body = resp.Body.String()
	for _, want := range []string{"domain:netflix.com", "full:fast.com", "keyword:nflx", "regexp:(?&lt;=x)y", "not applied"} {
		if !strings.Contains(body, want) {
			t.Fatalf("entries missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "hx-delete") {
		t.Fatal("geosite entries are deletable")
	}

	if resp := do(t, s, http.MethodGet, "/shunts/nope/entries"); resp.Code != http.StatusNotFound {
		t.Fatalf("unknown shunt: %d", resp.Code)
	}
}

func TestShuntsPageGeositeNoDataBadges(t *testing.T) {
	s, store, gs, _, _ := newGeositeTestServer(t)
	_ = store.AddGeositeShunt("zz-nocat", "geosite:zz-does-not-exist")

	body := do(t, s, http.MethodGet, "/shunts").Body.String()
	if !strings.Contains(body, "category not in database") || !strings.Contains(body, "0 entries") {
		t.Fatalf("missing-category badge:\n%s", body)
	}
	if body := do(t, s, http.MethodGet, "/shunts/zz-nocat/entries").Body.String(); !strings.Contains(body, "category not in database") {
		t.Fatalf("entries:\n%s", body)
	}

	gs.downloaded = false
	body = do(t, s, http.MethodGet, "/shunts").Body.String()
	if !strings.Contains(body, "database not downloaded") {
		t.Fatalf("not-downloaded badge:\n%s", body)
	}
}

func TestGeositeImportCreatesReferenceAndRemoveDeletesIt(t *testing.T) {
	s, store, _, rec, path := newGeositeTestServer(t)

	resp := do(t, s, http.MethodPost, "/geosite/import/DUCKDUCKGO")
	if resp.Code != http.StatusOK || rec.mutations != 1 {
		t.Fatalf("import: status %d, mutations %d", resp.Code, rec.mutations)
	}
	if msg, _ := toast(t, resp); !strings.Contains(msg, "Imported DUCKDUCKGO (1 domains)") {
		t.Fatalf("toast %q", msg)
	}
	sh, err := store.Get("DUCKDUCKGO")
	if err != nil || sh.Source != "geosite:duckduckgo" || len(sh.Entries) != 0 || !sh.Enabled {
		t.Fatalf("shunt = %+v, %v", sh, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "duckduckgo.com") {
		t.Fatalf("entries copied into the file:\n%s", raw)
	}
	// Entries are refused on it.
	if resp := post(t, s, "/shunts/DUCKDUCKGO/entries", nil); resp.Code == http.StatusOK {
		t.Fatal("entry added to a geosite shunt")
	}

	if resp := do(t, s, http.MethodPost, "/geosite/import/NOPE"); resp.Code != http.StatusNotFound {
		t.Fatalf("unknown category: %d", resp.Code)
	}
	if resp := do(t, s, http.MethodPost, "/geosite/import/manual"); resp.Code != http.StatusNotFound { // not a category
		t.Fatalf("import over manual: %d", resp.Code)
	}

	resp = do(t, s, http.MethodDelete, "/geosite/import/DUCKDUCKGO")
	if resp.Code != http.StatusOK || rec.mutations != 2 {
		t.Fatalf("remove: status %d, mutations %d", resp.Code, rec.mutations)
	}
	if _, err := store.Get("DUCKDUCKGO"); err == nil {
		t.Fatal("shunt survived remove")
	}
	if !strings.Contains(resp.Body.String(), "Import") {
		t.Fatalf("row after remove:\n%s", resp.Body.String())
	}
	if resp := do(t, s, http.MethodDelete, "/geosite/import/manual"); resp.Code != http.StatusConflict {
		t.Fatalf("remove manual via geosite: %d", resp.Code)
	}
}

func TestGeositePageFromIndex(t *testing.T) {
	s, store, gs, _, _ := newGeositeTestServer(t)
	_ = store.AddGeositeShunt("NETFLIX", "geosite:netflix")
	body := do(t, s, http.MethodGet, "/geosite").Body.String()
	if !strings.Contains(body, `data-name="DUCKDUCKGO"`) || !strings.Contains(body, `data-name="NETFLIX"`) ||
		strings.Count(body, "Imported") != 1 {
		t.Fatalf("geosite page:\n%s", body)
	}
	gs.downloaded = false
	if body := do(t, s, http.MethodGet, "/geosite").Body.String(); !strings.Contains(body, "Download Database") {
		t.Fatal("no download prompt without a database")
	}
}
