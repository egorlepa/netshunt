package shunt_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/egorlepa/netshunt/internal/shunt"
)

// fakeProvider serves categories from a map; calls counts lookups.
type fakeProvider struct {
	cats  map[string][]string
	calls int
}

func (f *fakeProvider) Entries(category string) ([]string, bool) {
	f.calls++
	e, ok := f.cats[strings.ToLower(category)]
	return e, ok
}

func geoStore(t *testing.T, cats map[string][]string) (*shunt.Store, *fakeProvider, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shunts.yaml")
	s := shunt.NewStore(path)
	p := &fakeProvider{cats: cats}
	s.SetGeositeProvider(p)
	return s, p, path
}

func values(entries []shunt.Entry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Value+"@"+e.Shunt)
	}
	return out
}

func TestEnabledEntriesExpandsGeosite(t *testing.T) {
	s, _, _ := geoStore(t, map[string][]string{
		"netflix": {"domain:Netflix.com", "full:fast.com", "keyword:nflx", `regexp:^nflx\d+\.net$`},
	})
	if err := s.Create(shunt.Shunt{Name: "M", Enabled: true, Entries: []shunt.Entry{{Value: "a.com"}, {Value: "domain:netflix.com"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddGeositeShunt("NETFLIX", "geosite:netflix"); err != nil {
		t.Fatal(err)
	}
	entries, err := s.EnabledEntries()
	if err != nil {
		t.Fatal(err)
	}
	// domain:netflix.com is deduplicated against the manual shunt (first
	// wins); the geosite value is normalised (lowercase).
	want := []string{"a.com@M", "domain:netflix.com@M", "full:fast.com@NETFLIX", "keyword:nflx@NETFLIX", `regexp:^nflx\d+\.net$@NETFLIX`}
	if got := values(entries); !slices.Equal(got, want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}

	// Disabled geosite shunt contributes nothing.
	if err := s.SetEnabled("NETFLIX", false); err != nil {
		t.Fatal(err)
	}
	entries, _ = s.EnabledEntries()
	if len(entries) != 2 {
		t.Fatalf("entries with geosite disabled = %v", values(entries))
	}
}

func TestGeositeWithoutProviderOrData(t *testing.T) {
	s := tempStore(t) // no provider
	if err := s.AddGeositeShunt("G", "geosite:g"); err != nil {
		t.Fatal(err)
	}
	entries, _ := s.EnabledEntries()
	if len(entries) != 0 {
		t.Fatalf("entries without provider = %v", values(entries))
	}
	missing, _ := s.GeositeMissing()
	if len(missing) != 1 || missing[0].Name != "G" {
		t.Fatalf("missing = %+v", missing)
	}

	s2, _, _ := geoStore(t, map[string][]string{"g": {"domain:g.com"}})
	_ = s2.AddGeositeShunt("G", "geosite:g")
	_ = s2.AddGeositeShunt("Z", "geosite:zz-does-not-exist")
	missing, _ = s2.GeositeMissing()
	if len(missing) != 1 || missing[0].Name != "Z" {
		t.Fatalf("missing = %+v", missing)
	}
	sh, _ := s2.Get("Z")
	if n, ok := s2.EntryCount(*sh); ok || n != 0 {
		t.Fatalf("EntryCount(Z) = %d, %v", n, ok)
	}
}

func TestGeositeShuntRefusesEntryMutations(t *testing.T) {
	s, _, _ := geoStore(t, map[string][]string{"g": {"domain:g.com"}})
	if err := s.AddGeositeShunt("G", "geosite:g"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddEntry("G", "x.com"); !errors.Is(err, shunt.ErrGeositeManaged) {
		t.Fatalf("AddEntry: %v", err)
	}
	if _, err := s.AddEntries("G", []string{"x.com"}); !errors.Is(err, shunt.ErrGeositeManaged) {
		t.Fatalf("AddEntries: %v", err)
	}
	if err := s.RemoveEntry("G", "domain:g.com"); !errors.Is(err, shunt.ErrGeositeManaged) {
		t.Fatalf("RemoveEntry: %v", err)
	}
	if !strings.Contains(shunt.ErrGeositeManaged.Error(), "Geosite page") {
		t.Fatalf("message %q", shunt.ErrGeositeManaged)
	}
}

func TestAddGeositeShunt(t *testing.T) {
	s, _, path := geoStore(t, map[string][]string{"g": {"domain:g.com"}})
	_ = s.Create(shunt.Shunt{Name: "manual", Enabled: true})
	if err := s.AddGeositeShunt("manual", "geosite:g"); err == nil {
		t.Fatal("geosite shunt over a manual one")
	}
	if err := s.AddGeositeShunt("G", "netflix"); err == nil {
		t.Fatal("non-geosite source accepted")
	}
	if err := s.AddGeositeShunt("G", "geosite:g"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddGeositeShunt("G", "geosite:g"); err != nil {
		t.Fatalf("re-import: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Count(string(raw), "name: G") != 1 || strings.Contains(string(raw), "g.com") {
		t.Fatalf("file:\n%s", raw)
	}
}

const oldShape = `shunts:
    - name: manual
      enabled: true
      entries:
        - value: a.com
    - name: YOUTUBE
      enabled: true
      source: geosite:youtube
      entries:
        - value: domain:youtube.com
        - value: domain:ytimg.com
    - name: EMPTY
      enabled: true
      source: geosite:empty
      entries: []
`

func TestLoadDropsCopiedGeositeEntriesAndNormalizesOnce(t *testing.T) {
	s, _, path := geoStore(t, map[string][]string{"youtube": {"domain:youtube.com", "domain:googlevideo.com"}})
	if err := os.WriteFile(path, []byte(oldShape), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(path, old, old)

	// Loading drops them in memory: entries come from the provider.
	sh, err := s.Get("YOUTUBE")
	if err != nil {
		t.Fatal(err)
	}
	if len(sh.Entries) != 0 {
		t.Fatalf("copied entries kept in memory: %+v", sh.Entries)
	}
	got, ok := s.Entries(*sh)
	if !ok || len(got) != 2 || got[1].Value != "domain:googlevideo.com" {
		t.Fatalf("expanded = %+v, %v", got, ok)
	}
	// Reads do not write.
	if fi, _ := os.Stat(path); !fi.ModTime().Equal(old) {
		t.Fatal("file rewritten by a read")
	}

	n, m, err := s.NormalizeGeosite()
	if err != nil || n != 1 || m != 2 {
		t.Fatalf("NormalizeGeosite = %d, %d, %v", n, m, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "youtube.com") || !strings.Contains(string(raw), "a.com") ||
		!strings.Contains(string(raw), "source: geosite:youtube") {
		t.Fatalf("normalised file:\n%s", raw)
	}
	fi1, _ := os.Stat(path)

	// Second run: nothing to do, nothing written.
	n, m, err = s.NormalizeGeosite()
	if err != nil || n != 0 || m != 0 {
		t.Fatalf("second NormalizeGeosite = %d, %d, %v", n, m, err)
	}
	if fi2, _ := os.Stat(path); !fi2.ModTime().Equal(fi1.ModTime()) {
		t.Fatal("clean file rewritten")
	}
	// A fresh store on the clean file has nothing to normalise either.
	if n, _, _ := shunt.NewStore(path).NormalizeGeosite(); n != 0 {
		t.Fatalf("fresh store normalised %d", n)
	}
}

func TestExportWritesGeositeAsReference(t *testing.T) {
	s, _, _ := geoStore(t, map[string][]string{"g": {"domain:g.com"}})
	_ = s.Create(shunt.Shunt{Name: "M", Enabled: true, Entries: []shunt.Entry{{Value: "m.com"}}})
	_ = s.AddGeositeShunt("G", "geosite:g")
	for _, export := range []func() ([]byte, error){s.ExportAll, func() ([]byte, error) { return s.ExportShunt("G") }} {
		data, err := export()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "g.com") || !strings.Contains(string(data), "source: geosite:g") {
			t.Fatalf("export:\n%s", data)
		}
	}
}

func TestImportOldShapeDropsGeositeEntries(t *testing.T) {
	s, _, path := geoStore(t, map[string][]string{"youtube": {"domain:youtube.com"}})
	// Invalid entries under a geosite shunt are not validated: they are dropped.
	data := strings.Replace(oldShape, "        - value: domain:ytimg.com\n", "        - value: domain:ytimg.com\n        - value: regexp:(\n", 1)
	if err := s.ImportShunts([]byte(data)); err != nil {
		t.Fatal(err)
	}
	m, _ := s.Get("manual")
	if len(m.Entries) != 1 {
		t.Fatalf("manual entries = %+v", m.Entries)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "ytimg") || strings.Contains(string(raw), "regexp:(") {
		t.Fatalf("file:\n%s", raw)
	}
	// Both shapes: a reference without entries imports too.
	ref := "shunts: [{name: zz-nocat, enabled: true, source: \"geosite:zz-does-not-exist\"}]"
	if err := s.ImportShunts([]byte(ref)); err != nil {
		t.Fatal(err)
	}
	if sh, err := s.Get("zz-nocat"); err != nil || !sh.IsGeosite() {
		t.Fatalf("reference import: %+v, %v", sh, err)
	}
}

func TestCountsIncludeExpandedEntries(t *testing.T) {
	s, _, _ := geoStore(t, map[string][]string{
		"g": {"domain:g.com", "full:h.com", "regexp:(?<=x)y"}, // one RE2 cannot compile
	})
	_ = s.Create(shunt.Shunt{Name: "M", Enabled: true, Entries: []shunt.Entry{{Value: "m.com"}, {Value: "1.2.3.4"}}})
	_ = s.Create(shunt.Shunt{Name: "off", Enabled: false, Entries: []shunt.Entry{{Value: "x.com"}}})
	_ = s.AddGeositeShunt("G", "geosite:g")
	total, enabled, entries, err := s.Counts()
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || enabled != 2 || entries != 4 {
		t.Fatalf("Counts = %d, %d, %d; want 3, 2, 4", total, enabled, entries)
	}
	sh, _ := s.Get("G")
	if n, ok := s.EntryCount(*sh); !ok || n != 2 {
		t.Fatalf("EntryCount = %d, %v", n, ok)
	}
	// The invalid regexp still reaches EnabledEntries, so the matcher rejects
	// it and the reconciler logs it with the shunt name.
	all, _ := s.EnabledEntries()
	if !slices.Contains(values(all), "regexp:(?<=x)y@G") {
		t.Fatalf("entries = %v", values(all))
	}
}

func TestGeositeExpansionReusedWhileProviderUnchanged(t *testing.T) {
	cats := map[string][]string{"g": {"domain:a.example", "domain:b.example"}}
	s, p, _ := geoStore(t, cats)
	_ = s.AddGeositeShunt("G", "geosite:g")
	first, _ := s.EnabledEntries()
	_, _ = s.EnabledEntries()
	if p.calls < 2 {
		t.Fatalf("provider consulted %d times", p.calls)
	}
	// A refreshed database hands out a new slice: the expansion follows it.
	cats["g"] = []string{"domain:a.example"}
	second, _ := s.EnabledEntries()
	if len(first) != 2 || len(second) != 1 {
		t.Fatalf("first %v, second %v", values(first), values(second))
	}
}
