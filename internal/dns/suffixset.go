package dns

import (
	"bytes"
	"sort"
	"strings"
	"sync/atomic"
	"time"
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
	return s.matchLen(query) > 0
}

// MatchSuffix returns the shortest stored entry that is a domain-suffix of
// query (the one Match finds first), and whether there is one.
func (s *SuffixSet) MatchSuffix(query string) (string, bool) {
	n := s.matchLen(query)
	if n == 0 {
		return "", false
	}
	// n bytes of the reversed form are n bytes of query's tail ("example.com"
	// reversed is "com.example." for the same length plus the dot).
	return query[len(query)-(n-1):], true
}

// matchLen returns the length of the reverse-labeled form (trailing dot
// included) of the shortest stored suffix of query, 0 when none matches.
func (s *SuffixSet) matchLen(query string) int {
	n := s.Len()
	if n == 0 || query == "" {
		return 0
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
			return i + 1
		}
	}
	return 0
}

// SizeBytes is the memory the set's data and offset table take.
func (s *SuffixSet) SizeBytes() int {
	return cap(s.data) + 4*cap(s.offsets)
}

// BuildSuffixSet constructs a SuffixSet from a streaming callback. The build
// function should call add() for each domain to include. Duplicates are
// silently collapsed. Empty domains are ignored. add copies the bytes into
// the set before returning, so the slice may alias a scanner buffer that the
// caller reuses; no per-domain string is allocated.
func BuildSuffixSet(build func(add func(domain []byte))) *SuffixSet {
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
		build(func(d []byte) {
			if len(d) == 0 {
				return
			}
			start := len(raw)
			raw = reverseLabelsAppendBytes(raw, d)
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

// reverseLabelsAppendBytes is reverseLabelsAppend for a byte slice, used by
// the build so a streamed domain never becomes a string.
func reverseLabelsAppendBytes(dst, d []byte) []byte {
	end := len(d)
	for end > 0 {
		start := bytes.LastIndexByte(d[:end], '.') + 1
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
	set     atomic.Pointer[SuffixSet]
	builtAt atomic.Int64 // UnixNano of the last Replace, 0 before
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
// swaps it in. Returns the number of unique entries installed. A nil build
// installs an empty set.
func (m *BlocklistMatcher) Replace(build func(add func(domain []byte))) int {
	s := BuildSuffixSet(build)
	m.set.Store(s)
	m.builtAt.Store(time.Now().UnixNano())
	return s.Len()
}

// MatchSuffix returns the stored suffix that blocks domain, if any.
func (m *BlocklistMatcher) MatchSuffix(domain string) (string, bool) {
	return m.set.Load().MatchSuffix(domain)
}

// SizeBytes is the memory of the active set (data plus offsets).
func (m *BlocklistMatcher) SizeBytes() int {
	return m.set.Load().SizeBytes()
}

// BuiltAt is when the active set was installed, zero before the first
// Replace.
func (m *BlocklistMatcher) BuiltAt() time.Time {
	ns := m.builtAt.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// Len returns the number of entries in the active set.
func (m *BlocklistMatcher) Len() int {
	return m.set.Load().Len()
}
