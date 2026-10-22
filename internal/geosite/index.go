package geosite

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Index is a lazy, per-category view of a dlc.dat file.
//
// The file is never held in memory. On first use, and whenever the file's
// size or mtime changes, it is scanned once at the top level: each GeoSite
// block's offset, length, country_code and number of domain fields is
// recorded, the domain payloads are skipped by length (no per-domain
// allocation). That index is about a hundred bytes per category (1545
// categories in the v2fly file). Entries then decodes a single category by
// ReadAt and caches the result until the file changes.
//
// Every public call stats the file, so a download (rename over the old
// file) takes effect on the next call without an explicit invalidation.
// Safe for concurrent use. The DNS path never calls it: only reconcile,
// mutations and the web UI do.
type Index struct {
	path   string
	logger *slog.Logger

	mu      sync.RWMutex
	valid   bool     // the fields below describe the file identified by st
	st      fileStat // exists=false: file missing
	err     error    // indexing failed (corrupt file); cats is empty
	cats    map[string]catRef
	infos   []CategoryInfo // sorted by name
	decoded map[string][]string
}

// catRef locates one GeoSite block inside the file.
type catRef struct {
	off   int64
	size  int
	count int
}

// fileStat identifies a version of the file on disk.
type fileStat struct {
	size    int64
	modTime int64 // UnixNano
	exists  bool
}

// NewIndex returns an index over the dlc.dat file at path. Nothing is read
// until the first call. A nil logger discards.
func NewIndex(path string, logger *slog.Logger) *Index {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Index{path: path, logger: logger}
}

// FileInfo reports whether the file exists, its mtime and the number of
// categories it holds.
func (x *Index) FileInfo() FileInfo {
	x.rlockCurrent()
	defer x.mu.RUnlock()
	if !x.st.exists {
		return FileInfo{}
	}
	return FileInfo{
		Downloaded:    true,
		LastModified:  time.Unix(0, x.st.modTime),
		CategoryCount: len(x.infos),
	}
}

// Categories returns every category with its domain count, sorted by name.
// A missing file is an empty list without error; a file that cannot be
// indexed returns the indexing error.
func (x *Index) Categories() ([]CategoryInfo, error) {
	x.rlockCurrent()
	defer x.mu.RUnlock()
	return slices.Clone(x.infos), x.err
}

// Entries returns the category's domains in xray prefix notation, in file
// order:
//   - DomainRoot  -> "domain:value"
//   - DomainFull  -> "full:value"
//   - DomainPlain -> "keyword:value"
//   - DomainRegex -> "regexp:value"
//
// The lookup is case-insensitive. ok is false when the file is missing,
// cannot be read, or has no such category. The returned slice is shared with
// the cache: callers must not modify it.
func (x *Index) Entries(category string) (entries []string, ok bool) {
	key := strings.ToLower(category)

	x.rlockCurrent()
	_, known := x.cats[key]
	entries, hit := x.decoded[key]
	x.mu.RUnlock()
	if hit {
		return entries, true
	}
	if !known {
		return nil, false
	}

	x.mu.Lock()
	defer x.mu.Unlock()
	return x.decodeLocked(key)
}

// rlockCurrent returns with x.mu read-locked and the index matching the
// file on disk as of the stat it made.
func (x *Index) rlockCurrent() {
	st, statErr := statPath(x.path)
	x.mu.RLock()
	if statErr == nil && x.valid && x.st == st {
		return
	}
	x.mu.RUnlock()

	x.mu.Lock()
	if statErr != nil || !x.valid || x.st != st {
		x.reindexLocked()
	}
	x.mu.Unlock()
	x.mu.RLock()
}

// reindexLocked opens the file and rebuilds the index from it. Caller holds
// x.mu for writing.
func (x *Index) reindexLocked() {
	f, err := os.Open(x.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			x.reset(fileStat{}, nil)
			return
		}
		x.reset(fileStat{}, fmt.Errorf("open geosite file: %w", err))
		return
	}
	defer func() { _ = f.Close() }()
	x.indexFromLocked(f)
}

// indexFromLocked rebuilds the index from an open file, identified by its
// own fstat so a rename between stat and open cannot mix two versions.
func (x *Index) indexFromLocked(f *os.File) {
	fi, err := f.Stat()
	if err != nil {
		x.reset(fileStat{}, fmt.Errorf("stat geosite file: %w", err))
		return
	}
	st := fileStat{size: fi.Size(), modTime: fi.ModTime().UnixNano(), exists: true}
	start := time.Now()
	cats, infos, domains, err := scanIndex(io.NewSectionReader(f, 0, st.size), st.size)
	if err != nil {
		x.reset(st, fmt.Errorf("index geosite file: %w", err))
		x.logger.Warn("geosite index failed", "path", x.path, "error", err)
		return
	}
	x.reset(st, nil)
	x.cats, x.infos = cats, infos
	x.logger.Info("geosite index built", "path", x.path, "bytes", st.size,
		"categories", len(infos), "domains", domains, "duration", time.Since(start).Round(time.Millisecond))
}

func (x *Index) reset(st fileStat, err error) {
	x.valid = true
	x.st = st
	x.err = err
	x.cats = nil
	x.infos = nil
	x.decoded = nil
}

// decodeLocked decodes one category from the file, caching the result.
// Caller holds x.mu for writing.
func (x *Index) decodeLocked(key string) ([]string, bool) {
	if e, ok := x.decoded[key]; ok {
		return e, true
	}
	f, err := os.Open(x.path)
	if err != nil {
		x.reindexLocked()
		return nil, false
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !x.valid ||
		x.st != (fileStat{size: fi.Size(), modTime: fi.ModTime().UnixNano(), exists: true}) {
		x.indexFromLocked(f)
	}
	ref, ok := x.cats[key]
	if !ok {
		return nil, false
	}
	buf := make([]byte, ref.size)
	if _, err := f.ReadAt(buf, ref.off); err != nil {
		x.logger.Warn("geosite category read failed", "category", key, "error", err)
		return nil, false
	}
	cat, err := parseGeoSite(buf)
	if err != nil {
		x.logger.Warn("geosite category decode failed", "category", key, "error", err)
		return nil, false
	}
	entries := prefixedEntries(cat.Domains)
	if x.decoded == nil {
		x.decoded = make(map[string][]string)
	}
	x.decoded[key] = entries
	return entries, true
}

func prefixedEntries(domains []Domain) []string {
	entries := make([]string, 0, len(domains))
	for _, d := range domains {
		switch d.Type {
		case DomainRoot:
			entries = append(entries, "domain:"+d.Value)
		case DomainFull:
			entries = append(entries, "full:"+d.Value)
		case DomainPlain:
			entries = append(entries, "keyword:"+d.Value)
		case DomainRegex:
			entries = append(entries, "regexp:"+d.Value)
		}
	}
	return entries
}

func statPath(path string) (fileStat, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fileStat{}, nil
		}
		return fileStat{}, err
	}
	return fileStat{size: fi.Size(), modTime: fi.ModTime().UnixNano(), exists: true}, nil
}

// scanIndex walks the GeoSiteList at the top level. For every GeoSite block
// it reads country_code and counts the domain fields, skipping each domain's
// payload by its length. Allocations are per category, not per domain.
// A code that repeats (case-insensitively) keeps its first block, as the
// former whole-file lookup did.
func scanIndex(r io.Reader, size int64) (map[string]catRef, []CategoryInfo, int, error) {
	sc := &scanner{r: bufio.NewReaderSize(r, 32<<10), size: size}
	cats := make(map[string]catRef)
	var infos []CategoryInfo
	total := 0
	for {
		tag, err := binary.ReadUvarint(sc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, 0, fmt.Errorf("GeoSiteList tag at %d: %w", sc.pos, err)
		}
		field, wire := tag>>3, int(tag&7)
		if field != 1 || wire != 2 {
			if err := sc.skipField(wire); err != nil {
				return nil, nil, 0, fmt.Errorf("skip GeoSiteList field at %d: %w", sc.pos, err)
			}
			continue
		}
		n, err := sc.length()
		if err != nil {
			return nil, nil, 0, fmt.Errorf("GeoSite length at %d: %w", sc.pos, err)
		}
		off := sc.pos
		code, count, err := sc.geoSite(off + n)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("GeoSite at %d: %w", off, err)
		}
		key := strings.ToLower(code)
		if _, dup := cats[key]; dup {
			continue
		}
		cats[key] = catRef{off: off, size: int(n), count: count}
		infos = append(infos, CategoryInfo{Name: code, DomainCount: count})
		total += count
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return cats, infos, total, nil
}

// scanner reads protobuf wire format from a buffered stream, tracking the
// absolute offset.
type scanner struct {
	r    *bufio.Reader
	pos  int64
	size int64
	buf  []byte // reused for country codes
}

func (s *scanner) ReadByte() (byte, error) {
	b, err := s.r.ReadByte()
	if err == nil {
		s.pos++
	}
	return b, err
}

func (s *scanner) varint() (uint64, error) {
	v, err := binary.ReadUvarint(s)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return v, err
}

// length reads a length prefix and checks it against the rest of the file.
func (s *scanner) length() (int64, error) {
	v, err := s.varint()
	if err != nil {
		return 0, err
	}
	if v > uint64(s.size-s.pos) {
		return 0, errors.New("length-delimited field exceeds data")
	}
	return int64(v), nil
}

func (s *scanner) skip(n int64) error {
	for n > 0 {
		step := n
		if step > 1<<30 {
			step = 1 << 30
		}
		d, err := s.r.Discard(int(step))
		s.pos += int64(d)
		n -= int64(d)
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

func (s *scanner) skipField(wire int) error {
	switch wire {
	case 0:
		_, err := s.varint()
		return err
	case 1:
		return s.skip(8)
	case 2:
		n, err := s.length()
		if err != nil {
			return err
		}
		return s.skip(n)
	case 5:
		return s.skip(4)
	default:
		return fmt.Errorf("unknown wire type %d", wire)
	}
}

// geoSite reads one GeoSite message ending at end: the country_code and the
// number of domain fields.
func (s *scanner) geoSite(end int64) (code string, count int, err error) {
	for s.pos < end {
		tag, err := s.varint()
		if err != nil {
			return "", 0, err
		}
		field, wire := tag>>3, int(tag&7)
		switch {
		case field == 1 && wire == 2: // country_code
			n, err := s.length()
			if err != nil {
				return "", 0, err
			}
			if s.pos+n > end {
				return "", 0, errors.New("country_code exceeds GeoSite")
			}
			if int64(cap(s.buf)) < n {
				s.buf = make([]byte, n)
			}
			b := s.buf[:n]
			if _, err := io.ReadFull(s.r, b); err != nil {
				return "", 0, err
			}
			s.pos += n
			code = string(b)
		case field == 2 && wire == 2: // domain
			n, err := s.length()
			if err != nil {
				return "", 0, err
			}
			if s.pos+n > end {
				return "", 0, errors.New("domain exceeds GeoSite")
			}
			if err := s.skip(n); err != nil {
				return "", 0, err
			}
			count++
		default:
			if err := s.skipField(wire); err != nil {
				return "", 0, err
			}
		}
	}
	if s.pos != end {
		return "", 0, errors.New("field overruns GeoSite")
	}
	return code, count, nil
}
