package dns

import (
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/egorlepa/netshunt/internal/shunt"
)

// matcherRules holds an immutable snapshot of domain matching rules.
type matcherRules struct {
	suffixes map[string]struct{}
	exact    map[string]struct{}
	keywords []string
	regexps  []*regexp.Regexp
}

// Matcher tests domain names against a set of rules loaded from shunt entries.
// It supports suffix, exact, keyword, and regexp matching. All methods are safe
// for concurrent use. Rules are swapped atomically on update.
type Matcher struct {
	rules atomic.Pointer[matcherRules]
}

// NewMatcher returns an empty Matcher.
func NewMatcher() *Matcher {
	m := &Matcher{}
	m.rules.Store(&matcherRules{
		suffixes: make(map[string]struct{}),
		exact:    make(map[string]struct{}),
	})
	return m
}

// Match reports whether domain matches any loaded rule.
// The domain should be in lowercase without a trailing dot.
func (m *Matcher) Match(domain string) bool {
	r := m.rules.Load()

	// Exact match.
	if _, ok := r.exact[domain]; ok {
		return true
	}

	// Suffix match: walk up parent domains.
	// For "a.b.example.com", check "a.b.example.com", "b.example.com", "example.com".
	d := domain
	for {
		if _, ok := r.suffixes[d]; ok {
			return true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}

	// Keyword match.
	for _, kw := range r.keywords {
		if strings.Contains(domain, kw) {
			return true
		}
	}

	// Regexp match.
	for _, re := range r.regexps {
		if re.MatchString(domain) {
			return true
		}
	}

	return false
}

// Update replaces all matching rules from the given entries.
// Only domain-type entries are used; IP/CIDR entries are ignored.
func (m *Matcher) Update(entries []shunt.Entry) {
	r := &matcherRules{
		suffixes: make(map[string]struct{}),
		exact:    make(map[string]struct{}),
	}

	for _, e := range entries {
		switch e.Type() {
		case shunt.EntryDomainSuffix:
			r.suffixes[strings.ToLower(e.DomainValue())] = struct{}{}
		case shunt.EntryDomainFull:
			r.exact[strings.ToLower(e.DomainValue())] = struct{}{}
		case shunt.EntryDomainKeyword:
			r.keywords = append(r.keywords, strings.ToLower(e.DomainValue()))
		case shunt.EntryDomainRegexp:
			if re, err := regexp.Compile(e.DomainValue()); err == nil {
				r.regexps = append(r.regexps, re)
			}
		}
	}

	m.rules.Store(r)
}

// ReplaceSuffixes atomically replaces the rule set with a fresh suffix-only
// matcher. build is called once and should invoke add for every domain to
// register. Domains are expected to be already lowercased. Duplicates are
// silently collapsed by the underlying map. Returns the number of unique
// suffixes installed.
//
// This is the low-memory path used by the blocklist — it avoids building any
// intermediate slice of entries, so peak heap on a large list (~1M domains)
// is just the resulting map.
func (m *Matcher) ReplaceSuffixes(build func(add func(domain string))) int {
	r := &matcherRules{
		suffixes: make(map[string]struct{}),
		exact:    make(map[string]struct{}),
	}
	if build != nil {
		build(func(d string) {
			if len(d) != 0 {
				r.suffixes[d] = struct{}{}
			}
		})
	}
	m.rules.Store(r)
	return len(r.suffixes)
}

// Stats returns counts of each rule type.
func (m *Matcher) Stats() (suffixes, exact, keywords, regexps int) {
	r := m.rules.Load()
	return len(r.suffixes), len(r.exact), len(r.keywords), len(r.regexps)
}
