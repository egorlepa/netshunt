package blocklist

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Stream invokes emit for every normalized domain from every enabled source
// cache file. Domains are yielded as byte slices that alias the scanner's
// buffer - emit must copy the bytes if it intends to retain them past the
// callback.
//
// perSource, if non-nil, is called once per enabled source after its file has
// been streamed, with the number of domains emitted from that source
// (pre-cross-source-dedup) and the error that stopped the stream: a missing
// cache file (never downloaded, or deleted) or a read error. A source that
// errors still contributes whatever was emitted before the error.
//
// This is the low-memory apply path: no []string, no dedup map, no
// []shunt.Entry is built inside this call. The caller's emit closure is
// expected to insert directly into the destination data structure
// (typically the matcher's suffix set).
func (s *Store) Stream(emit func(domain []byte), perSource func(id string, count int, err error)) {
	for _, st := range s.States() {
		if !st.Enabled {
			continue
		}
		preset := PresetByID(st.ID)
		if preset == nil {
			continue
		}
		path := CachePath(s.CacheDir(), st.ID)
		n := 0
		err := StreamFile(path, preset.Format, func(b []byte) {
			emit(b)
			n++
		})
		if perSource != nil {
			perSource(st.ID, n, err)
		}
	}
}

// Fingerprint describes the inputs of the matcher Stream builds: for every
// enabled source, in Presets order, its id and the size and mtime of its
// cache file, or "missing" when the file cannot be stat'ed. Two equal
// fingerprints mean Stream would emit the same domains, so the matcher need
// not be rebuilt. Only os.Stat is called, no file is read.
func (s *Store) Fingerprint() string {
	var b strings.Builder
	for _, st := range s.States() {
		if !st.Enabled || PresetByID(st.ID) == nil {
			continue
		}
		b.WriteString(st.ID)
		fi, err := os.Stat(CachePath(s.CacheDir(), st.ID))
		if err != nil {
			b.WriteString(":missing;")
			continue
		}
		b.WriteByte(':')
		b.WriteString(strconv.FormatInt(fi.Size(), 10))
		b.WriteByte(':')
		b.WriteString(strconv.FormatInt(fi.ModTime().UnixNano(), 10))
		b.WriteByte(';')
	}
	return b.String()
}

// CleanCache removes from the cache dir every regular file <id>.txt whose id
// has no preset (lists of sources dropped from Presets) and every *.tmp left
// by an interrupted download. Other names are never touched. Returns the
// removed file names. A missing cache dir is not an error.
func (s *Store) CleanCache() (removed []string, err error) {
	entries, err := os.ReadDir(s.CacheDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read blocklist cache dir: %w", err)
	}
	var errs []error
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		name := e.Name()
		stale := strings.HasSuffix(name, ".tmp")
		if id, ok := strings.CutSuffix(name, ".txt"); ok && PresetByID(id) == nil {
			stale = true
		}
		if !stale {
			continue
		}
		if err := os.Remove(filepath.Join(s.CacheDir(), name)); err != nil {
			errs = append(errs, err)
			continue
		}
		removed = append(removed, name)
	}
	return removed, errors.Join(errs...)
}
