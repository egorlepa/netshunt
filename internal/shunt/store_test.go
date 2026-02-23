package shunt_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/egorlepa/netshunt/internal/shunt"
)

func tempStore(t *testing.T) *shunt.Store {
	t.Helper()
	dir := t.TempDir()
	return shunt.NewStore(filepath.Join(dir, "shunts.yaml"))
}

func TestCreateAndGet(t *testing.T) {
	s := tempStore(t)

	err := s.Create(shunt.Shunt{Name: "YouTube", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	sh, err := s.Get("YouTube")
	if err != nil {
		t.Fatal(err)
	}
	if sh.Name != "YouTube" || !sh.Enabled {
		t.Fatalf("unexpected shunt: %+v", sh)
	}
}

func TestCreateDuplicate(t *testing.T) {
	s := tempStore(t)

	_ = s.Create(shunt.Shunt{Name: "Test"})
	err := s.Create(shunt.Shunt{Name: "Test"})
	if err == nil {
		t.Fatal("expected error for duplicate shunt")
	}
}

func TestAddAndRemoveEntry(t *testing.T) {
	s := tempStore(t)
	_ = s.Create(shunt.Shunt{Name: "Test", Enabled: true})

	if err := s.AddEntry("Test", "youtube.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddEntry("Test", "google.com"); err != nil {
		t.Fatal(err)
	}

	// Duplicate should fail.
	if err := s.AddEntry("Test", "youtube.com"); err == nil {
		t.Fatal("expected error for duplicate entry")
	}

	sh, _ := s.Get("Test")
	if len(sh.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(sh.Entries))
	}

	if err := s.RemoveEntry("Test", "youtube.com"); err != nil {
		t.Fatal(err)
	}

	sh, _ = s.Get("Test")
	if len(sh.Entries) != 1 || sh.Entries[0].Value != "google.com" {
		t.Fatalf("unexpected entries after remove: %+v", sh.Entries)
	}
}

func TestEnabledEntries(t *testing.T) {
	s := tempStore(t)

	_ = s.Create(shunt.Shunt{Name: "A", Enabled: true, Entries: []shunt.Entry{{Value: "a.com"}, {Value: "shared.com"}}})
	_ = s.Create(shunt.Shunt{Name: "B", Enabled: true, Entries: []shunt.Entry{{Value: "b.com"}, {Value: "shared.com"}}})
	_ = s.Create(shunt.Shunt{Name: "C", Enabled: false, Entries: []shunt.Entry{{Value: "c.com"}}})

	entries, err := s.EnabledEntries()
	if err != nil {
		t.Fatal(err)
	}

	// A(a.com, shared.com) + B(b.com) = 3 (shared.com deduplicated, C disabled).
	if len(entries) != 3 {
		t.Fatalf("expected 3 enabled entries, got %d: %+v", len(entries), entries)
	}
}

func TestSetEnabled(t *testing.T) {
	s := tempStore(t)
	_ = s.Create(shunt.Shunt{Name: "Test", Enabled: true})

	_ = s.SetEnabled("Test", false)
	sh, _ := s.Get("Test")
	if sh.Enabled {
		t.Fatal("expected disabled")
	}

	_ = s.SetEnabled("Test", true)
	sh, _ = s.Get("Test")
	if !sh.Enabled {
		t.Fatal("expected enabled")
	}
}

func TestDelete(t *testing.T) {
	s := tempStore(t)
	_ = s.Create(shunt.Shunt{Name: "Test"})

	if err := s.Delete("Test"); err != nil {
		t.Fatal(err)
	}

	shunts, _ := s.List()
	if len(shunts) != 0 {
		t.Fatalf("expected 0 shunts after delete, got %d", len(shunts))
	}
}

func TestImportExport(t *testing.T) {
	s := tempStore(t)
	_ = s.Create(shunt.Shunt{Name: "YouTube", Enabled: true, Entries: []shunt.Entry{{Value: "youtube.com"}}})

	data, err := s.ExportAll()
	if err != nil {
		t.Fatal(err)
	}

	// Import into a fresh store.
	s2 := tempStore(t)
	if err := s2.ImportShunts(data); err != nil {
		t.Fatal(err)
	}

	shunts, _ := s2.List()
	if len(shunts) != 1 || shunts[0].Name != "YouTube" {
		t.Fatalf("unexpected imported shunts: %+v", shunts)
	}
}

func TestEnsureDefaultShunt(t *testing.T) {
	s := tempStore(t)

	if err := s.EnsureDefaultShunt(); err != nil {
		t.Fatal(err)
	}

	shunts, _ := s.List()
	if len(shunts) != 1 || shunts[0].Name != shunt.DefaultShuntName {
		t.Fatalf("expected default shunt, got: %+v", shunts)
	}

	// Should not create a second one.
	_ = s.EnsureDefaultShunt()
	shunts, _ = s.List()
	if len(shunts) != 1 {
		t.Fatalf("expected 1 shunt, got %d", len(shunts))
	}
}

func TestEntryType(t *testing.T) {
	tests := []struct {
		value string
		want  shunt.EntryType
	}{
		{"youtube.com", shunt.EntryDomain},
		{"1.2.3.4", shunt.EntryIP},
		{"10.0.0.0/8", shunt.EntryCIDR},
		{"2001:db8::/32", shunt.EntryCIDR},
		{"::1", shunt.EntryIP},
		{"sub.domain.example.com", shunt.EntryDomain},
	}

	for _, tt := range tests {
		e := shunt.Entry{Value: tt.value}
		if got := e.Type(); got != tt.want {
			t.Errorf("Entry(%q).Type() = %d, want %d", tt.value, got, tt.want)
		}
	}
}

func TestImportExportFile(t *testing.T) {
	s := tempStore(t)
	_ = s.Create(shunt.Shunt{Name: "A", Enabled: true, Entries: []shunt.Entry{{Value: "a.com"}}})
	_ = s.Create(shunt.Shunt{Name: "B", Enabled: false, Entries: []shunt.Entry{{Value: "b.com"}}})

	data, err := s.ExportShunt("A")
	if err != nil {
		t.Fatal(err)
	}

	// Write to file and re-import.
	f := filepath.Join(t.TempDir(), "export.yaml")
	os.WriteFile(f, data, 0644)

	s2 := tempStore(t)
	raw, _ := os.ReadFile(f)
	if err := s2.ImportShunts(raw); err != nil {
		t.Fatal(err)
	}

	shunts, _ := s2.List()
	if len(shunts) != 1 || shunts[0].Name != "A" {
		t.Fatalf("expected only shunt A, got: %+v", shunts)
	}
}
