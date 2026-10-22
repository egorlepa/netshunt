package shunt

import (
	"errors"
	"fmt"
	"os"
	"slices"
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

// GeositeProvider supplies the entries of a geosite category, in prefix
// notation ("domain:", "full:", "keyword:", "regexp:"). ok is false when it
// has no data for the category (database missing, category not in it). The
// returned slice must not be modified; returning the same slice for the same
// data lets the Store reuse its expansion. *geosite.Index implements it.
type GeositeProvider interface {
	Entries(category string) ([]string, bool)
}

// ErrGeositeManaged is returned for entry mutations on a geosite shunt.
var ErrGeositeManaged = errors.New("geosite shunts are managed from the Geosite page")

// Store manages shunts with file-backed persistence.
//
// A geosite shunt (Source "geosite:<category>") is stored as a reference
// without entries; its entries come from the GeositeProvider whenever they
// are needed. Entries found under a geosite shunt in the file (written by
// versions up to 1.5.7~rc23, or hand-edited) are dropped on load and never
// written back.
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

	// copiedShunts/copiedEntries count the geosite shunts that carried
	// entries in the file at the last parse, and those entries. Reset by
	// save, which writes the file without them.
	copiedShunts  int
	copiedEntries int

	geosite  GeositeProvider
	geoCache map[string]expansion
}

// expansion is a geosite category turned into entries, kept while the
// provider returns the same slice.
type expansion struct {
	src     *string // &src[0] of the provider slice it was built from
	n       int
	entries []Entry // normalised, invalid ones included (the matcher rejects and the reconciler reports them)
	valid   int     // entries that pass Validate
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

// SetGeositeProvider sets the source of geosite shunt entries. With none
// set, geosite shunts contribute no entries and report no data.
func (s *Store) SetGeositeProvider(p GeositeProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.geosite = p
	s.geoCache = nil
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
			if shunts[i].IsGeosite() {
				return fmt.Errorf("shunt %q: %w", shuntName, ErrGeositeManaged)
			}
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
	if shunts[idx].IsGeosite() {
		return res, fmt.Errorf("shunt %q: %w", shuntName, ErrGeositeManaged)
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
			if shunts[i].IsGeosite() {
				return fmt.Errorf("shunt %q: %w", shuntName, ErrGeositeManaged)
			}
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

// EnabledEntries returns all entries from all enabled shunts, deduplicated,
// geosite shunts expanded from the provider. Entry.Shunt names the shunt.
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
		src := sh.Entries
		if sh.IsGeosite() {
			x, _ := s.expandLocked(sh)
			src = x.entries
		}
		for _, e := range src {
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

// Entries returns the entries a shunt applies: its own, or for a geosite
// shunt the category's entries from the provider. ok is false for a geosite
// shunt the provider has no data for.
func (s *Store) Entries(sh Shunt) (entries []Entry, ok bool) {
	if !sh.IsGeosite() {
		return slices.Clone(sh.Entries), true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.expandLocked(sh)
	return slices.Clone(x.entries), ok
}

// EntryCount returns the number of valid entries a shunt applies (see
// Entries). For a manual shunt it is len(sh.Entries), as before.
func (s *Store) EntryCount(sh Shunt) (n int, ok bool) {
	if !sh.IsGeosite() {
		return len(sh.Entries), true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.expandLocked(sh)
	return x.valid, ok
}

// Counts returns the number of shunts, of enabled shunts, and the entries
// the enabled shunts apply (geosite shunts expanded, not deduplicated
// across shunts).
func (s *Store) Counts() (total, enabled, entries int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	shunts, err := s.load()
	if err != nil {
		return 0, 0, 0, err
	}
	for _, sh := range shunts {
		if !sh.Enabled {
			continue
		}
		enabled++
		if sh.IsGeosite() {
			x, _ := s.expandLocked(sh)
			entries += x.valid
			continue
		}
		entries += len(sh.Entries)
	}
	return len(shunts), enabled, entries, nil
}

// GeositeMissing returns the enabled geosite shunts the provider has no
// data for (database missing, or category not in it), in file order.
func (s *Store) GeositeMissing() ([]Shunt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	shunts, err := s.load()
	if err != nil {
		return nil, err
	}
	var out []Shunt
	for _, sh := range shunts {
		if !sh.Enabled || !sh.IsGeosite() {
			continue
		}
		if _, ok := s.expandLocked(sh); !ok {
			out = append(out, sh)
		}
	}
	return out, nil
}

// expandLocked turns a geosite shunt's category into entries, reusing the
// previous expansion while the provider hands out the same slice. The
// result is shared: callers copy before handing it out. Caller holds s.mu.
func (s *Store) expandLocked(sh Shunt) (expansion, bool) {
	cat, _ := sh.GeositeCategory()
	if s.geosite == nil {
		return expansion{}, false
	}
	src, ok := s.geosite.Entries(cat)
	if !ok {
		return expansion{}, false
	}
	if len(src) == 0 {
		return expansion{}, true
	}
	key := strings.ToLower(cat)
	if x, hit := s.geoCache[key]; hit && x.src == &src[0] && x.n == len(src) {
		return x, true
	}
	x := expansion{src: &src[0], n: len(src), entries: make([]Entry, 0, len(src))}
	for _, v := range src {
		x.entries = append(x.entries, Entry{Value: normalizeEntry(v)})
		if Validate(v) == nil {
			x.valid++
		}
	}
	if s.geoCache == nil {
		s.geoCache = make(map[string]expansion)
	}
	s.geoCache[key] = x
	return x, true
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
// Geosite shunts are imported as references: entries listed under them (the
// pre-reference export format) are dropped.
func (s *Store) ImportShunts(data []byte) error {
	var imported shuntsFile
	if err := yaml.Unmarshal(data, &imported); err != nil {
		return fmt.Errorf("parse import data: %w", err)
	}
	var bad []string
	for i := range imported.Shunts {
		sh := &imported.Shunts[i]
		if sh.IsGeosite() {
			sh.Entries = nil // a reference: entries come from the database
			continue
		}
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

// AddGeositeShunt creates an enabled shunt referencing a geosite category
// (source "geosite:<category>"). It is a no-op for an existing geosite shunt
// with that name and source, and an error for a manual shunt with that name.
func (s *Store) AddGeositeShunt(name, source string) error {
	if !strings.HasPrefix(source, GeositeSourcePrefix) {
		return fmt.Errorf("source %q is not a geosite source", source)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	shunts, err := s.load()
	if err != nil {
		return err
	}
	for i := range shunts {
		if shunts[i].Name != name {
			continue
		}
		if !shunts[i].IsGeosite() {
			return fmt.Errorf("shunt %q already exists and is not a geosite shunt", name)
		}
		if shunts[i].Source == source {
			return nil
		}
		shunts[i].Source = source
		return s.save(shunts)
	}
	shunts = append(shunts, Shunt{Name: name, Enabled: true, Source: source})
	return s.save(shunts)
}

// NormalizeGeosite rewrites the file without the entries stored under
// geosite shunts by earlier versions, when there are any. It returns how
// many geosite shunts carried entries and how many entries were dropped
// (0, 0 when the file was already clean, in which case nothing is written).
// The daemon calls it once at start; nothing else needs to, since every
// save writes the file without them anyway.
func (s *Store) NormalizeGeosite() (shunts, entries int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	list, err := s.load()
	if err != nil {
		return 0, 0, err
	}
	if s.copiedShunts == 0 {
		return 0, 0, nil
	}
	shunts, entries = s.copiedShunts, s.copiedEntries
	if err := s.save(list); err != nil {
		return 0, 0, err
	}
	return shunts, entries, nil
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
		if sh.IsGeosite() {
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
	s.copiedShunts, s.copiedEntries = stripGeositeEntries(shunts)
	s.cached = shunts
	s.cacheStat = st
	s.cacheOK = true
	return cloneShunts(shunts), nil
}

// save writes shunts atomically and makes them the cached state. Caller
// holds s.mu. On a write error the cache is left as it was, so the next read
// reflects what is actually on disk.
func (s *Store) save(shunts []Shunt) error {
	stripGeositeEntries(shunts)
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
	s.copiedShunts, s.copiedEntries = 0, 0
	return nil
}

// stripGeositeEntries drops the entries of geosite shunts in place and
// returns how many shunts carried any, and how many entries were dropped.
func stripGeositeEntries(shunts []Shunt) (n, entries int) {
	for i := range shunts {
		if shunts[i].IsGeosite() && len(shunts[i].Entries) > 0 {
			n++
			entries += len(shunts[i].Entries)
			shunts[i].Entries = nil
		}
	}
	return n, entries
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
