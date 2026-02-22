package group_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/egorlepa/netshunt/internal/group"
)

func tempStore(t *testing.T) *group.Store {
	t.Helper()
	dir := t.TempDir()
	return group.NewStore(filepath.Join(dir, "groups.yaml"))
}

func TestCreateAndGet(t *testing.T) {
	s := tempStore(t)

	err := s.Create(group.Group{Name: "YouTube", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	g, err := s.Get("YouTube")
	if err != nil {
		t.Fatal(err)
	}
	if g.Name != "YouTube" || !g.Enabled {
		t.Fatalf("unexpected group: %+v", g)
	}
}

func TestCreateDuplicate(t *testing.T) {
	s := tempStore(t)

	_ = s.Create(group.Group{Name: "Test"})
	err := s.Create(group.Group{Name: "Test"})
	if err == nil {
		t.Fatal("expected error for duplicate group")
	}
}

func TestAddAndRemoveEntry(t *testing.T) {
	s := tempStore(t)
	_ = s.Create(group.Group{Name: "Test", Enabled: true})

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

	g, _ := s.Get("Test")
	if len(g.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(g.Entries))
	}

	if err := s.RemoveEntry("Test", "youtube.com"); err != nil {
		t.Fatal(err)
	}

	g, _ = s.Get("Test")
	if len(g.Entries) != 1 || g.Entries[0].Value != "google.com" {
		t.Fatalf("unexpected entries after remove: %+v", g.Entries)
	}
}

func TestEnabledEntries(t *testing.T) {
	s := tempStore(t)

	_ = s.Create(group.Group{Name: "A", Enabled: true, Entries: []group.Entry{{Value: "a.com"}, {Value: "shared.com"}}})
	_ = s.Create(group.Group{Name: "B", Enabled: true, Entries: []group.Entry{{Value: "b.com"}, {Value: "shared.com"}}})
	_ = s.Create(group.Group{Name: "C", Enabled: false, Entries: []group.Entry{{Value: "c.com"}}})

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
	_ = s.Create(group.Group{Name: "Test", Enabled: true})

	_ = s.SetEnabled("Test", false)
	g, _ := s.Get("Test")
	if g.Enabled {
		t.Fatal("expected disabled")
	}

	_ = s.SetEnabled("Test", true)
	g, _ = s.Get("Test")
	if !g.Enabled {
		t.Fatal("expected enabled")
	}
}

func TestDelete(t *testing.T) {
	s := tempStore(t)
	_ = s.Create(group.Group{Name: "Test"})

	if err := s.Delete("Test"); err != nil {
		t.Fatal(err)
	}

	groups, _ := s.List()
	if len(groups) != 0 {
		t.Fatalf("expected 0 groups after delete, got %d", len(groups))
	}
}

func TestImportExport(t *testing.T) {
	s := tempStore(t)
	_ = s.Create(group.Group{Name: "YouTube", Enabled: true, Entries: []group.Entry{{Value: "youtube.com"}}})

	data, err := s.ExportAll()
	if err != nil {
		t.Fatal(err)
	}

	// Import into a fresh store.
	s2 := tempStore(t)
	if err := s2.ImportGroups(data); err != nil {
		t.Fatal(err)
	}

	groups, _ := s2.List()
	if len(groups) != 1 || groups[0].Name != "YouTube" {
		t.Fatalf("unexpected imported groups: %+v", groups)
	}
}

func TestEnsureDefaultGroup(t *testing.T) {
	s := tempStore(t)

	if err := s.EnsureDefaultGroup(); err != nil {
		t.Fatal(err)
	}

	groups, _ := s.List()
	if len(groups) != 1 || groups[0].Name != group.DefaultGroupName {
		t.Fatalf("expected default group, got: %+v", groups)
	}

	// Should not create a second one.
	_ = s.EnsureDefaultGroup()
	groups, _ = s.List()
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
}

func TestEntryType(t *testing.T) {
	tests := []struct {
		value string
		want  group.EntryType
	}{
		{"youtube.com", group.EntryDomain},
		{"1.2.3.4", group.EntryIP},
		{"10.0.0.0/8", group.EntryCIDR},
		{"2001:db8::/32", group.EntryCIDR},
		{"::1", group.EntryIP},
		{"sub.domain.example.com", group.EntryDomain},
	}

	for _, tt := range tests {
		e := group.Entry{Value: tt.value}
		if got := e.Type(); got != tt.want {
			t.Errorf("Entry(%q).Type() = %d, want %d", tt.value, got, tt.want)
		}
	}
}

func TestImportExportFile(t *testing.T) {
	s := tempStore(t)
	_ = s.Create(group.Group{Name: "A", Enabled: true, Entries: []group.Entry{{Value: "a.com"}}})
	_ = s.Create(group.Group{Name: "B", Enabled: false, Entries: []group.Entry{{Value: "b.com"}}})

	data, err := s.ExportGroup("A")
	if err != nil {
		t.Fatal(err)
	}

	// Write to file and re-import.
	f := filepath.Join(t.TempDir(), "export.yaml")
	os.WriteFile(f, data, 0644)

	s2 := tempStore(t)
	raw, _ := os.ReadFile(f)
	if err := s2.ImportGroups(raw); err != nil {
		t.Fatal(err)
	}

	groups, _ := s2.List()
	if len(groups) != 1 || groups[0].Name != "A" {
		t.Fatalf("expected only group A, got: %+v", groups)
	}
}
