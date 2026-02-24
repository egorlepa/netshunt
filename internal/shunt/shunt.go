package shunt

import (
	"net"
	"strings"
)

// EntryType classifies a host entry.
type EntryType int

const (
	EntryDomain  EntryType = iota // example.com
	EntryIP                       // 1.2.3.4
	EntryCIDR                     // 1.2.3.0/24
)

// Entry is a single host entry (domain, IP, or CIDR).
type Entry struct {
	Value string `yaml:"value"`
}

// Type returns the detected type of this entry.
func (e Entry) Type() EntryType {
	if _, _, err := net.ParseCIDR(e.Value); err == nil {
		return EntryCIDR
	}
	if ip := net.ParseIP(e.Value); ip != nil {
		return EntryIP
	}
	return EntryDomain
}

// IsDomain returns true if the entry is a domain name (not IP/CIDR).
func (e Entry) IsDomain() bool {
	return e.Type() == EntryDomain
}

// Shunt is a named collection of host entries.
type Shunt struct {
	Name        string  `yaml:"name"`
	Description string  `yaml:"description,omitempty"`
	Enabled     bool    `yaml:"enabled"`
	Source      string  `yaml:"source,omitempty"` // e.g. "geosite:netflix"
	Entries     []Entry `yaml:"entries"`
}

// HasEntry returns true if the shunt contains the given value.
func (s *Shunt) HasEntry(value string) bool {
	value = normalizeEntry(value)
	for _, e := range s.Entries {
		if normalizeEntry(e.Value) == value {
			return true
		}
	}
	return false
}

// AddEntry adds an entry if it doesn't already exist. Returns true if added.
func (s *Shunt) AddEntry(value string) bool {
	value = normalizeEntry(value)
	if s.HasEntry(value) {
		return false
	}
	s.Entries = append(s.Entries, Entry{Value: value})
	return true
}

// RemoveEntry removes an entry by value. Returns true if removed.
func (s *Shunt) RemoveEntry(value string) bool {
	value = normalizeEntry(value)
	for i, e := range s.Entries {
		if normalizeEntry(e.Value) == value {
			s.Entries = append(s.Entries[:i], s.Entries[i+1:]...)
			return true
		}
	}
	return false
}

func normalizeEntry(s string) string {
	s = strings.TrimSpace(s)

	// Strip URL scheme (http://, https://).
	if i := strings.Index(s, "://"); i != -1 {
		s = s[i+3:]
	}

	// Strip path, query, fragment.
	if i := strings.IndexByte(s, '/'); i != -1 {
		s = s[:i]
	}

	// Strip port (but not from CIDR like 10.0.0.0/8 — already handled above).
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}

	return strings.ToLower(strings.TrimSpace(s))
}
