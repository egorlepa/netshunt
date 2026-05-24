package dns

import (
	"bytes"
	"sort"
	"strings"
	"sync/atomic"
)

// SuffixSet is a compact, immutable set of domain suffixes optimised for the
// blocklist hot path. Entries are stored reverse-labeled with a trailing dot,
// packed into a single byte buffer with a uint32 offset table. A suffix match
// is one binary search per label boundary in the query, zero allocations.
//
// Memory layout for ~500k Hagezi-style entries is about 15 MB
// (~3× tighter than map[string]struct{}), with no per-string-header overhead
// and no map bucket overhead.
type SuffixSet struct {
	data    []byte   // concatenated reverse-labeled entries (each ends with '.')
	offsets []uint32 // offsets[i] = start of entry i; offsets[n] = len(data)
}

// Len returns the number of unique entries stored.
func (s *SuffixSet) Len() int {
	if len(s.offsets) == 0 {
		return 0
	}
	return len(s.offsets) - 1
}

// at returns the byte slice of entry i (including trailing dot).
func (s *SuffixSet) at(i int) []byte {
	return s.data[s.offsets[i]:s.offsets[i+1]]
}

// Match reports whether any stored entry is a domain-suffix of query.
// query should be lowercase, no trailing dot. Zero allocations on hot path.
func (s *SuffixSet) Match(query string) bool {
	n := s.Len()
	if n == 0 || query == "" {
		return false
	}
	var buf [256]byte
	q := reverseLabelsAppend(buf[:0], query)
	for i, c := range q {
		if c != '.' {
			continue
		}
		cand := q[:i+1] // include the trailing dot
		idx := sort.Search(n, func(j int) bool {
			return bytes.Compare(s.at(j), cand) >= 0
		})
		if idx < n && bytes.Equal(s.at(idx), cand) {
			return true
		}
	}
	return false
}

// BuildSuffixSet constructs a SuffixSet from a streaming callback. The build
// function should call add() for each domain to include. Duplicates are
// silently collapsed. Empty strings are ignored.
func BuildSuffixSet(build func(add func(domain string))) *SuffixSet {
	// Stream into reversed-form bytes + per-entry (start, length).
	// We sort indices (not strings) and compact into the final layout.
	type entry struct {
		start  uint32
		length uint32
	}
	var (
		raw     []byte
		entries []entry
	)
	if build != nil {
		build(func(d string) {
			if d == "" {
				return
			}
			start := len(raw)
			raw = reverseLabelsAppend(raw, d)
			entries = append(entries, entry{
				start:  uint32(start),
				length: uint32(len(raw) - start),
			})
		})
	}

	if len(entries) == 0 {
		return &SuffixSet{}
	}

	sort.Slice(entries, func(i, j int) bool {
		a := raw[entries[i].start : entries[i].start+entries[i].length]
		b := raw[entries[j].start : entries[j].start+entries[j].length]
		return bytes.Compare(a, b) < 0
	})

	// Dedup consecutive equal entries.
	n := 0
	for i := range entries {
		if i > 0 {
			cur := raw[entries[i].start : entries[i].start+entries[i].length]
			prev := raw[entries[i-1].start : entries[i-1].start+entries[i-1].length]
			if bytes.Equal(cur, prev) {
				continue
			}
		}
		entries[n] = entries[i]
		n++
	}
	entries = entries[:n]

	// Pack into the final compact layout. After this, `raw` can be GC'd.
	data := make([]byte, 0, len(raw))
	offsets := make([]uint32, 0, n+1)
	for _, e := range entries {
		offsets = append(offsets, uint32(len(data)))
		data = append(data, raw[e.start:e.start+e.length]...)
	}
	offsets = append(offsets, uint32(len(data)))

	return &SuffixSet{data: data, offsets: offsets}
}

// reverseLabelsAppend writes the reverse-labeled form of d (with trailing dot)
// to dst and returns the resulting slice. Reusing a caller-supplied buffer
// keeps lookups allocation-free.
//
//	"foo.bar.example.com" → "com.example.bar.foo."
func reverseLabelsAppend(dst []byte, d string) []byte {
	end := len(d)
	for end > 0 {
		start := strings.LastIndexByte(d[:end], '.') + 1
		dst = append(dst, d[start:end]...)
		dst = append(dst, '.')
		end = start - 1
		if end < 0 {
			break
		}
	}
	return dst
}

// BlocklistMatcher is a thread-safe wrapper around SuffixSet supporting
// atomic replacement (for blocklist refresh) and lock-free reads.
type BlocklistMatcher struct {
	set atomic.Pointer[SuffixSet]
}

// NewBlocklistMatcher returns a matcher with an empty set installed.
func NewBlocklistMatcher() *BlocklistMatcher {
	m := &BlocklistMatcher{}
	m.set.Store(&SuffixSet{})
	return m
}

// Match returns true iff any stored entry is a domain-suffix of domain.
func (m *BlocklistMatcher) Match(domain string) bool {
	return m.set.Load().Match(domain)
}

// Replace builds a fresh SuffixSet from the supplied stream and atomically
// swaps it in. Returns the number of unique entries installed.
func (m *BlocklistMatcher) Replace(build func(add func(domain string))) int {
	s := BuildSuffixSet(build)
	m.set.Store(s)
	return s.Len()
}

// Len returns the number of entries in the active set.
func (m *BlocklistMatcher) Len() int {
	return m.set.Load().Len()
}
