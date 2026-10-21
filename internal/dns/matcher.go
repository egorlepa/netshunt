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
	return m.rules.Load().match(domain)
}

// matchRules is Match that also returns the rules it used, so a caller can
// tell afterwards whether an Update happened in between.
func (m *Matcher) matchRules(domain string) (bool, *matcherRules) {
	r := m.rules.Load()
	return r.match(domain), r
}

// changedSince reports whether the rules were replaced after r was loaded.
func (m *Matcher) changedSince(r *matcherRules) bool {
	return m.rules.Load() != r
}

func (r *matcherRules) match(domain string) bool {

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

// Snapshot returns a Matcher frozen on the current rules. Later Update calls
// on m do not affect it.
func (m *Matcher) Snapshot() *Matcher {
	s := &Matcher{}
	s.rules.Store(m.rules.Load())
	return s
}

// Update replaces all matching rules from the given entries.
// Only domain-type entries are used; IP/CIDR entries are ignored.
func (m *Matcher) Update(entries []shunt.Entry) {
	r := &matcherRules{
		suffixes: make(map[string]struct{}),
		exact:    make(map[string]struct{}),
	}

	for _, e := range entries {
		// Normalised like the store does on add, so a value hand-typed in
		// YAML with upper case or a URL still keys on the lowercase query
		// name the forwarder and tracker use.
		e = shunt.Entry{Value: shunt.NormalizeEntry(e.Value)}
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

// Stats returns counts of each rule type.
func (m *Matcher) Stats() (suffixes, exact, keywords, regexps int) {
	r := m.rules.Load()
	return len(r.suffixes), len(r.exact), len(r.keywords), len(r.regexps)
}
