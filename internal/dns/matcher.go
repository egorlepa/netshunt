package dns

import (
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/egorlepa/netshunt/internal/shunt"
)

// matcherRules holds an immutable snapshot of domain matching rules.
// Each map value and the parallel name slices hold the name of the shunt
// the rule came from (the first one, when several shunts carry the same
// rule), for the activity feed.
type matcherRules struct {
	suffixes     map[string]string
	exact        map[string]string
	keywords     []string
	keywordShunt []string
	regexps      []*regexp.Regexp
	regexpShunt  []string
}

// MatchKind is the kind of rule a name matched.
type MatchKind int

const (
	MatchSuffix MatchKind = iota
	MatchExact
	MatchKeyword
	MatchRegexp
)

// MatchInfo describes the rule a name matched: the shunt it belongs to, its
// kind and its value (the suffix, the exact name, the keyword or the
// pattern).
type MatchInfo struct {
	Shunt string
	Kind  MatchKind
	Rule  string
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
		suffixes: make(map[string]string),
		exact:    make(map[string]string),
	})
	return m
}

// Match reports whether domain matches any loaded rule.
// The domain should be in lowercase without a trailing dot.
func (m *Matcher) Match(domain string) bool {
	return m.rules.Load().match(domain)
}

// Lookup is Match that also says which rule matched.
func (m *Matcher) Lookup(domain string) (MatchInfo, bool) {
	return m.rules.Load().lookup(domain)
}

// firstMatch returns the first of names that matches a loaded rule ("" when
// none does), the rule it matched and the rules it used, so a caller can
// tell afterwards whether an Update happened in between.
func (m *Matcher) firstMatch(names []string) (string, MatchInfo, *matcherRules) {
	r := m.rules.Load()
	for _, n := range names {
		if info, ok := r.lookup(n); ok {
			return n, info, r
		}
	}
	return "", MatchInfo{}, r
}

// changedSince reports whether the rules were replaced after r was loaded.
func (m *Matcher) changedSince(r *matcherRules) bool {
	return m.rules.Load() != r
}

func (r *matcherRules) match(domain string) bool {
	_, ok := r.lookup(domain)
	return ok
}

// lookup checks exact, suffix, keyword and regexp rules in that order and
// returns the first rule that matches.
func (r *matcherRules) lookup(domain string) (MatchInfo, bool) {
	// Exact match.
	if sh, ok := r.exact[domain]; ok {
		return MatchInfo{Shunt: sh, Kind: MatchExact, Rule: domain}, true
	}

	// Suffix match: walk up parent domains.
	// For "a.b.example.com", check "a.b.example.com", "b.example.com", "example.com".
	d := domain
	for {
		if sh, ok := r.suffixes[d]; ok {
			return MatchInfo{Shunt: sh, Kind: MatchSuffix, Rule: d}, true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}

	// Keyword match.
	for i, kw := range r.keywords {
		if strings.Contains(domain, kw) {
			return MatchInfo{Shunt: r.keywordShunt[i], Kind: MatchKeyword, Rule: kw}, true
		}
	}

	// Regexp match.
	for i, re := range r.regexps {
		if re.MatchString(domain) {
			return MatchInfo{Shunt: r.regexpShunt[i], Kind: MatchRegexp, Rule: re.String()}, true
		}
	}

	return MatchInfo{}, false
}

// Snapshot returns a Matcher frozen on the current rules. Later Update calls
// on m do not affect it.
func (m *Matcher) Snapshot() *Matcher {
	s := &Matcher{}
	s.rules.Store(m.rules.Load())
	return s
}

// Update replaces all matching rules from the given entries.
// Only domain-type entries are used; IP/CIDR entries are ignored. Domain
// entries that cannot be applied (a regexp that does not compile, a domain
// or keyword with characters no DNS name has) are skipped and returned.
func (m *Matcher) Update(entries []shunt.Entry) (rejected []shunt.Entry) {
	r := &matcherRules{
		suffixes: make(map[string]string),
		exact:    make(map[string]string),
	}
	// setOnce keeps the first shunt that carries a rule.
	setOnce := func(m map[string]string, k, shunt string) {
		if _, ok := m[k]; !ok {
			m[k] = shunt
		}
	}

	for _, orig := range entries {
		if !orig.IsDomain() {
			continue
		}
		// Normalised like the store does on add, so a value hand-typed in
		// YAML with upper case or a URL still keys on the lowercase query
		// name the forwarder and tracker use.
		e := shunt.Entry{Value: shunt.NormalizeEntry(orig.Value)}
		if e.Type() == shunt.EntryDomainRegexp {
			re, err := regexp.Compile(e.DomainValue())
			if err != nil || e.DomainValue() == "" {
				rejected = append(rejected, orig)
				continue
			}
			r.regexps = append(r.regexps, re)
			r.regexpShunt = append(r.regexpShunt, orig.Shunt)
			continue
		}
		if shunt.Validate(e.Value) != nil {
			rejected = append(rejected, orig)
			continue
		}
		switch e.Type() {
		case shunt.EntryDomainSuffix:
			setOnce(r.suffixes, strings.ToLower(e.DomainValue()), orig.Shunt)
		case shunt.EntryDomainFull:
			setOnce(r.exact, strings.ToLower(e.DomainValue()), orig.Shunt)
		case shunt.EntryDomainKeyword:
			r.keywords = append(r.keywords, strings.ToLower(e.DomainValue()))
			r.keywordShunt = append(r.keywordShunt, orig.Shunt)
		}
	}

	m.rules.Store(r)
	return rejected
}

// Stats returns counts of each rule type.
func (m *Matcher) Stats() (suffixes, exact, keywords, regexps int) {
	r := m.rules.Load()
	return len(r.suffixes), len(r.exact), len(r.keywords), len(r.regexps)
}
