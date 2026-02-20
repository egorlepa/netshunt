package group

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/guras256/keenetic-split-tunnel/internal/platform"
)

const DefaultGroupName = "Default"

// groupsFile is the on-disk YAML structure.
type groupsFile struct {
	Groups []Group `yaml:"groups"`
}

// Store manages host groups with file-backed persistence.
type Store struct {
	mu   sync.Mutex
	path string
}

// NewStore creates a Store that reads/writes the given file path.
func NewStore(path string) *Store {
	return &Store{path: path}
}

// NewDefaultStore creates a Store using the default groups file path.
func NewDefaultStore() *Store {
	return NewStore(platform.GroupsFile)
}

// List returns all groups.
func (s *Store) List() ([]Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

// Get returns a group by name.
func (s *Store) Get(name string) (*Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	groups, err := s.load()
	if err != nil {
		return nil, err
	}
	for i := range groups {
		if groups[i].Name == name {
			return &groups[i], nil
		}
	}
	return nil, fmt.Errorf("group %q not found", name)
}

// Create adds a new group. Returns error if name already exists.
func (s *Store) Create(g Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	groups, err := s.load()
	if err != nil {
		return err
	}
	for _, existing := range groups {
		if existing.Name == g.Name {
			return fmt.Errorf("group %q already exists", g.Name)
		}
	}
	groups = append(groups, g)
	return s.save(groups)
}

// Update replaces an existing group entirely.
func (s *Store) Update(g Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	groups, err := s.load()
	if err != nil {
		return err
	}
	for i := range groups {
		if groups[i].Name == g.Name {
			groups[i] = g
			return s.save(groups)
		}
	}
	return fmt.Errorf("group %q not found", g.Name)
}

// Delete removes a group by name.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	groups, err := s.load()
	if err != nil {
		return err
	}
	for i := range groups {
		if groups[i].Name == name {
			groups = append(groups[:i], groups[i+1:]...)
			return s.save(groups)
		}
	}
	return fmt.Errorf("group %q not found", name)
}

// AddEntry adds an entry to a group. Deduplicates by value.
func (s *Store) AddEntry(groupName, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	groups, err := s.load()
	if err != nil {
		return err
	}
	for i := range groups {
		if groups[i].Name == groupName {
			if !groups[i].AddEntry(value) {
				return fmt.Errorf("entry %q already exists in group %q", value, groupName)
			}
			return s.save(groups)
		}
	}
	return fmt.Errorf("group %q not found", groupName)
}

// RemoveEntry removes an entry from a group.
func (s *Store) RemoveEntry(groupName, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	groups, err := s.load()
	if err != nil {
		return err
	}
	for i := range groups {
		if groups[i].Name == groupName {
			if !groups[i].RemoveEntry(value) {
				return fmt.Errorf("entry %q not found in group %q", value, groupName)
			}
			return s.save(groups)
		}
	}
	return fmt.Errorf("group %q not found", groupName)
}

// SetEnabled enables or disables a group.
func (s *Store) SetEnabled(name string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	groups, err := s.load()
	if err != nil {
		return err
	}
	for i := range groups {
		if groups[i].Name == name {
			groups[i].Enabled = enabled
			return s.save(groups)
		}
	}
	return fmt.Errorf("group %q not found", name)
}

// EnabledEntries returns all entries from all enabled groups, deduplicated.
func (s *Store) EnabledEntries() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	groups, err := s.load()
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var entries []Entry
	for _, g := range groups {
		if !g.Enabled {
			continue
		}
		for _, e := range g.Entries {
			key := normalizeEntry(e.Value)
			if seen[key] {
				continue
			}
			seen[key] = true
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// ExportGroup exports a single group as YAML bytes.
func (s *Store) ExportGroup(name string) ([]byte, error) {
	g, err := s.Get(name)
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(groupsFile{Groups: []Group{*g}})
}

// ExportAll exports all groups as YAML bytes.
func (s *Store) ExportAll() ([]byte, error) {
	groups, err := s.List()
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(groupsFile{Groups: groups})
}

// ImportGroups imports groups from YAML bytes. Merges with existing groups
// (overwrites groups with the same name).
func (s *Store) ImportGroups(data []byte) error {
	var imported groupsFile
	if err := yaml.Unmarshal(data, &imported); err != nil {
		return fmt.Errorf("parse import data: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	groups, err := s.load()
	if err != nil {
		return err
	}

	for _, ig := range imported.Groups {
		found := false
		for i := range groups {
			if groups[i].Name == ig.Name {
				groups[i] = ig
				found = true
				break
			}
		}
		if !found {
			groups = append(groups, ig)
		}
	}
	return s.save(groups)
}

// EnsureDefaultGroup creates the default group if no groups exist.
func (s *Store) EnsureDefaultGroup() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	groups, err := s.load()
	if err != nil {
		return err
	}
	if len(groups) > 0 {
		return nil
	}
	groups = append(groups, Group{
		Name:    DefaultGroupName,
		Enabled: true,
	})
	return s.save(groups)
}

func (s *Store) load() ([]Group, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read groups: %w", err)
	}
	var f groupsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse groups: %w", err)
	}
	return f.Groups, nil
}

func (s *Store) save(groups []Group) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return fmt.Errorf("create groups dir: %w", err)
	}
	data, err := yaml.Marshal(groupsFile{Groups: groups})
	if err != nil {
		return fmt.Errorf("marshal groups: %w", err)
	}
	return os.WriteFile(s.path, data, 0644)
}
