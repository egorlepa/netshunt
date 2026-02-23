package shunt

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/egorlepa/netshunt/internal/platform"
)

const DefaultShuntName = "Default"

// shuntsFile is the on-disk YAML structure.
type shuntsFile struct {
	Shunts []Shunt `yaml:"shunts"`
}

// Store manages shunts with file-backed persistence.
type Store struct {
	mu   sync.Mutex
	path string
}

// NewStore creates a Store that reads/writes the given file path.
func NewStore(path string) *Store {
	return &Store{path: path}
}

// NewDefaultStore creates a Store using the default shunts file path.
func NewDefaultStore() *Store {
	return NewStore(platform.ShuntsFile)
}

// List returns all shunts.
func (s *Store) List() ([]Shunt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

// Get returns a shunt by name.
func (s *Store) Get(name string) (*Shunt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	shunts, err := s.load()
	if err != nil {
		return nil, err
	}
	for i := range shunts {
		if shunts[i].Name == name {
			return &shunts[i], nil
		}
	}
	return nil, fmt.Errorf("shunt %q not found", name)
}

// Create adds a new shunt. Returns error if name already exists.
func (s *Store) Create(sh Shunt) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	shunts, err := s.load()
	if err != nil {
		return err
	}
	for _, existing := range shunts {
		if existing.Name == sh.Name {
			return fmt.Errorf("shunt %q already exists", sh.Name)
		}
	}
	shunts = append(shunts, sh)
	return s.save(shunts)
}

// Update replaces an existing shunt entirely.
func (s *Store) Update(sh Shunt) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	shunts, err := s.load()
	if err != nil {
		return err
	}
	for i := range shunts {
		if shunts[i].Name == sh.Name {
			shunts[i] = sh
			return s.save(shunts)
		}
	}
	return fmt.Errorf("shunt %q not found", sh.Name)
}

// Delete removes a shunt by name.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	shunts, err := s.load()
	if err != nil {
		return err
	}
	for i := range shunts {
		if shunts[i].Name == name {
			shunts = append(shunts[:i], shunts[i+1:]...)
			return s.save(shunts)
		}
	}
	return fmt.Errorf("shunt %q not found", name)
}

// AddEntry adds an entry to a shunt. Deduplicates by value.
func (s *Store) AddEntry(shuntName, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	shunts, err := s.load()
	if err != nil {
		return err
	}
	for i := range shunts {
		if shunts[i].Name == shuntName {
			if !shunts[i].AddEntry(value) {
				return fmt.Errorf("entry %q already exists in shunt %q", value, shuntName)
			}
			return s.save(shunts)
		}
	}
	return fmt.Errorf("shunt %q not found", shuntName)
}

// RemoveEntry removes an entry from a shunt.
func (s *Store) RemoveEntry(shuntName, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	shunts, err := s.load()
	if err != nil {
		return err
	}
	for i := range shunts {
		if shunts[i].Name == shuntName {
			if !shunts[i].RemoveEntry(value) {
				return fmt.Errorf("entry %q not found in shunt %q", value, shuntName)
			}
			return s.save(shunts)
		}
	}
	return fmt.Errorf("shunt %q not found", shuntName)
}

// SetEnabled enables or disables a shunt.
func (s *Store) SetEnabled(name string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	shunts, err := s.load()
	if err != nil {
		return err
	}
	for i := range shunts {
		if shunts[i].Name == name {
			shunts[i].Enabled = enabled
			return s.save(shunts)
		}
	}
	return fmt.Errorf("shunt %q not found", name)
}

// EnabledEntries returns all entries from all enabled shunts, deduplicated.
func (s *Store) EnabledEntries() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	shunts, err := s.load()
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var entries []Entry
	for _, sh := range shunts {
		if !sh.Enabled {
			continue
		}
		for _, e := range sh.Entries {
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

// ExportShunt exports a single shunt as YAML bytes.
func (s *Store) ExportShunt(name string) ([]byte, error) {
	sh, err := s.Get(name)
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(shuntsFile{Shunts: []Shunt{*sh}})
}

// ExportAll exports all shunts as YAML bytes.
func (s *Store) ExportAll() ([]byte, error) {
	shunts, err := s.List()
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(shuntsFile{Shunts: shunts})
}

// ImportShunts imports shunts from YAML bytes. Merges with existing shunts
// (overwrites shunts with the same name).
func (s *Store) ImportShunts(data []byte) error {
	var imported shuntsFile
	if err := yaml.Unmarshal(data, &imported); err != nil {
		return fmt.Errorf("parse import data: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	shunts, err := s.load()
	if err != nil {
		return err
	}

	for _, ish := range imported.Shunts {
		found := false
		for i := range shunts {
			if shunts[i].Name == ish.Name {
				shunts[i] = ish
				found = true
				break
			}
		}
		if !found {
			shunts = append(shunts, ish)
		}
	}
	return s.save(shunts)
}

// EnsureDefaultShunt creates the default shunt if no shunts exist.
func (s *Store) EnsureDefaultShunt() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	shunts, err := s.load()
	if err != nil {
		return err
	}
	if len(shunts) > 0 {
		return nil
	}
	shunts = append(shunts, Shunt{
		Name:    DefaultShuntName,
		Enabled: true,
	})
	return s.save(shunts)
}

func (s *Store) load() ([]Shunt, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read shunts: %w", err)
	}
	var f shuntsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse shunts: %w", err)
	}
	return f.Shunts, nil
}

func (s *Store) save(shunts []Shunt) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return fmt.Errorf("create shunts dir: %w", err)
	}
	data, err := yaml.Marshal(shuntsFile{Shunts: shunts})
	if err != nil {
		return fmt.Errorf("marshal shunts: %w", err)
	}
	return os.WriteFile(s.path, data, 0644)
}
