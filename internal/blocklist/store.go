package blocklist

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// SourceState is the persisted per-source state.
type SourceState struct {
	ID           string    `yaml:"id"`
	Enabled      bool      `yaml:"enabled"`
	LastFetched  time.Time `yaml:"last_fetched,omitempty"`
	DomainCount  int       `yaml:"domain_count,omitempty"`
	LastError    string    `yaml:"last_error,omitempty"`
	// ETag and LastModified carry validators returned by upstream so the next
	// fetch can issue a conditional GET (If-None-Match / If-Modified-Since).
	ETag         string `yaml:"etag,omitempty"`
	LastModified string `yaml:"last_modified,omitempty"`
}

// Meta is the on-disk blocklist metadata file.
type Meta struct {
	Sources []SourceState `yaml:"sources"`
}

// Store persists per-source state to a YAML file and provides thread-safe
// accessors. Cache files live under a separate directory passed to Reload.
type Store struct {
	path    string
	cacheDir string

	mu   sync.RWMutex
	meta Meta
}

// NewStore returns a Store bound to the given metadata file and cache dir.
// The file is loaded (or initialized from presets) on construction.
func NewStore(path, cacheDir string) (*Store, error) {
	s := &Store{path: path, cacheDir: cacheDir}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// load reads the YAML file, creating a defaults-populated file if missing.
// Any newly-added presets that aren't in the file are appended in their
// default-disabled state (except DefaultOn presets, which land enabled).
func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read blocklist meta: %w", err)
	}
	if err == nil {
		if err := yaml.Unmarshal(data, &s.meta); err != nil {
			return fmt.Errorf("parse blocklist meta: %w", err)
		}
	}

	// Merge presets: ensure every preset has a SourceState entry, drop
	// entries whose preset no longer exists.
	existing := make(map[string]SourceState, len(s.meta.Sources))
	for _, st := range s.meta.Sources {
		existing[st.ID] = st
	}
	merged := make([]SourceState, 0, len(Presets))
	for _, p := range Presets {
		if st, ok := existing[p.ID]; ok {
			merged = append(merged, st)
			continue
		}
		merged = append(merged, SourceState{ID: p.ID, Enabled: p.DefaultOn})
	}
	s.meta.Sources = merged

	return s.saveLocked()
}

// saveLocked writes the current meta atomically to disk. Must be called with
// s.mu held.
func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return fmt.Errorf("create blocklist dir: %w", err)
	}
	data, err := yaml.Marshal(s.meta)
	if err != nil {
		return fmt.Errorf("marshal blocklist meta: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("write blocklist meta: %w", err)
	}
	return os.Rename(tmp, s.path)
}

// State returns a copy of the SourceState for the given id, or zero value + false.
func (s *Store) State(id string) (SourceState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, st := range s.meta.Sources {
		if st.ID == id {
			return st, true
		}
	}
	return SourceState{}, false
}

// States returns a snapshot of all source states (order mirrors Presets).
func (s *Store) States() []SourceState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SourceState, len(s.meta.Sources))
	copy(out, s.meta.Sources)
	return out
}

// mutateSource applies fn to the SourceState with the given id and then
// persists the meta file. Lock is held across both the mutation and the write
// so readers never observe in-memory state that isn't yet on disk. Returns
// an error if id is unknown.
func (s *Store) mutateSource(id string, fn func(*SourceState)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.meta.Sources {
		if s.meta.Sources[i].ID == id {
			fn(&s.meta.Sources[i])
			return s.saveLocked()
		}
	}
	return fmt.Errorf("unknown blocklist source %q", id)
}

// SetEnabled toggles the enabled flag for a source.
func (s *Store) SetEnabled(id string, enabled bool) error {
	return s.mutateSource(id, func(st *SourceState) {
		st.Enabled = enabled
	})
}

// RecordFetch updates the last-fetched timestamp, domain count, validators,
// and clears any prior error for a source. Call on a successful 200 fetch.
func (s *Store) RecordFetch(id string, domainCount int, etag, lastModified string) error {
	return s.mutateSource(id, func(st *SourceState) {
		st.LastFetched = time.Now().UTC()
		st.DomainCount = domainCount
		st.LastError = ""
		st.ETag = etag
		st.LastModified = lastModified
	})
}

// RecordUnchanged marks a source as confirmed-fresh (304 response). Keeps the
// existing DomainCount and validators, refreshes LastFetched, clears any prior
// error.
func (s *Store) RecordUnchanged(id string) error {
	return s.mutateSource(id, func(st *SourceState) {
		st.LastFetched = time.Now().UTC()
		st.LastError = ""
	})
}

// RecordError stores the fetch error for a source. Keeps the previous
// DomainCount and LastFetched intact (stale cache still usable).
func (s *Store) RecordError(id string, errMsg string) error {
	return s.mutateSource(id, func(st *SourceState) {
		st.LastError = errMsg
	})
}

// CacheDir returns the directory where source caches are stored.
func (s *Store) CacheDir() string { return s.cacheDir }
