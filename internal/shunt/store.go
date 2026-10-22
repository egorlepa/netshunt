package shunt

import (
	"errors"
	"fmt"
	"os"
	"strings"
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
//
// The YAML file is the durable copy, but it is parsed only when it changes:
// Store keeps the last loaded state in memory together with the file's
// size and mtime, and every read hands out a deep copy of that state. A
// write goes to disk first (atomically) and then replaces the cached copy.
// If the file is edited by hand, the next read notices the changed stat and
// reloads it. Parsing 150 KB of YAML costs tens of milliseconds and a few MB
// of garbage on the router, which used to happen on every page view and
// every dashboard poll.
type Store struct {
	mu   sync.Mutex
	path string

	cached    []Shunt // nil until the first load; aliases nothing handed out
	cacheStat fileStat
	cacheOK   bool
}

// fileStat identifies a version of the file on disk.
type fileStat struct {
	size    int64
	modTime int64 // UnixNano
	exists  bool
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

// AddEntry adds an entry to a shunt. Deduplicates by value. An entry that
// fails Validate is rejected with an *InvalidEntryError.
func (s *Store) AddEntry(shuntName, value string) error {
	if err := Validate(value); err != nil {
		return err
	}
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

// BulkResult is the outcome of AddEntries.
type BulkResult struct {
	Added      int
	Duplicates int
	Rejected   []*InvalidEntryError
}

// AddEntries adds every non-blank value to a shunt in one load/save. Values
// failing Validate are collected in Rejected, duplicates counted.
func (s *Store) AddEntries(shuntName string, values []string) (BulkResult, error) {
	var res BulkResult
	s.mu.Lock()
	defer s.mu.Unlock()

	shunts, err := s.load()
	if err != nil {
		return res, err
	}
	idx := -1
	for i := range shunts {
		if shunts[i].Name == shuntName {
			idx = i
			break
		}
	}
	if idx < 0 {
		return res, fmt.Errorf("shunt %q not found", shuntName)
	}
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			continue
		}
		if err := Validate(v); err != nil {
			var ie *InvalidEntryError
			if errors.As(err, &ie) {
				res.Rejected = append(res.Rejected, ie)
			}
			continue
		}
		if shunts[idx].AddEntry(v) {
			res.Added++
		} else {
			res.Duplicates++
		}
	}
	if res.Added == 0 {
		return res, nil
	}
	return res, s.save(shunts)
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
			e.Shunt = sh.Name
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
// (overwrites shunts with the same name). Entry values are normalised; if
// any entry fails Validate nothing is imported and the error lists them.
func (s *Store) ImportShunts(data []byte) error {
	var imported shuntsFile
	if err := yaml.Unmarshal(data, &imported); err != nil {
		return fmt.Errorf("parse import data: %w", err)
	}
	var bad []string
	for i := range imported.Shunts {
		sh := &imported.Shunts[i]
		for j := range sh.Entries {
			if err := Validate(sh.Entries[j].Value); err != nil {
				var ie *InvalidEntryError
				if errors.As(err, &ie) {
					bad = append(bad, fmt.Sprintf("%s: %q (%s)", sh.Name, ie.Value, ie.Reason))
				}
				continue
			}
			sh.Entries[j].Value = normalizeEntry(sh.Entries[j].Value)
		}
	}
	if len(bad) > 0 {
		more := ""
		if len(bad) > 5 {
			more = fmt.Sprintf(" and %d more", len(bad)-5)
			bad = bad[:5]
		}
		return fmt.Errorf("import rejected, invalid entries: %s%s", strings.Join(bad, "; "), more)
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

// SyncGeositeShunt creates or fully replaces a shunt's entries from geosite
// data. Entries failing Validate (e.g. a regexp RE2 cannot compile) are
// left out and returned in skipped; they do not fail the sync.
func (s *Store) SyncGeositeShunt(name, source string, domains []string) (skipped []*InvalidEntryError, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	shunts, err := s.load()
	if err != nil {
		return nil, err
	}

	entries := make([]Entry, 0, len(domains))
	for _, d := range domains {
		if err := Validate(d); err != nil {
			var ie *InvalidEntryError
			if errors.As(err, &ie) {
				skipped = append(skipped, ie)
			}
			continue
		}
		entries = append(entries, Entry{Value: normalizeEntry(d)})
	}

	for i := range shunts {
		if shunts[i].Name == name {
			// Existing shunt with same name must be a geosite shunt.
			if shunts[i].Source == "" {
				return nil, fmt.Errorf("shunt %q already exists and is not a geosite shunt", name)
			}
			shunts[i].Source = source
			shunts[i].Entries = entries
			return skipped, s.save(shunts)
		}
	}

	shunts = append(shunts, Shunt{
		Name:    name,
		Enabled: true,
		Source:  source,
		Entries: entries,
	})
	return skipped, s.save(shunts)
}

// GeositeShunts returns all shunts that have a geosite source.
func (s *Store) GeositeShunts() ([]Shunt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	shunts, err := s.load()
	if err != nil {
		return nil, err
	}

	var result []Shunt
	for _, sh := range shunts {
		if strings.HasPrefix(sh.Source, "geosite:") {
			result = append(result, sh)
		}
	}
	return result, nil
}

// load returns a deep copy of the shunts, re-reading the file only when its
// size or mtime differs from the cached version. Caller holds s.mu.
func (s *Store) load() ([]Shunt, error) {
	st, err := statFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("stat shunts: %w", err)
	}
	if s.cacheOK && st == s.cacheStat {
		return cloneShunts(s.cached), nil
	}
	var shunts []Shunt
	if st.exists {
		data, err := os.ReadFile(s.path)
		if err != nil {
			return nil, fmt.Errorf("read shunts: %w", err)
		}
		var f shuntsFile
		if err := yaml.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parse shunts: %w", err)
		}
		shunts = f.Shunts
	}
	s.cached = shunts
	s.cacheStat = st
	s.cacheOK = true
	return cloneShunts(shunts), nil
}

// save writes shunts atomically and makes them the cached state. Caller
// holds s.mu. On a write error the cache is left as it was, so the next read
// reflects what is actually on disk.
func (s *Store) save(shunts []Shunt) error {
	data, err := yaml.Marshal(shuntsFile{Shunts: shunts})
	if err != nil {
		return fmt.Errorf("marshal shunts: %w", err)
	}
	if err := platform.WriteFileAtomic(s.path, data, 0644); err != nil {
		return err
	}
	st, err := statFile(s.path)
	if err != nil {
		s.cacheOK = false
		return nil
	}
	s.cached = cloneShunts(shunts)
	s.cacheStat = st
	s.cacheOK = true
	return nil
}

func statFile(path string) (fileStat, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fileStat{}, nil
		}
		return fileStat{}, err
	}
	return fileStat{size: fi.Size(), modTime: fi.ModTime().UnixNano(), exists: true}, nil
}

// cloneShunts deep-copies the slice so callers can mutate their copy
// without touching the cache (mutations only reach the cache through save).
func cloneShunts(in []Shunt) []Shunt {
	if in == nil {
		return nil
	}
	out := make([]Shunt, len(in))
	for i, sh := range in {
		out[i] = sh
		if sh.Entries != nil {
			out[i].Entries = make([]Entry, len(sh.Entries))
			copy(out[i].Entries, sh.Entries)
		}
	}
	return out
}
