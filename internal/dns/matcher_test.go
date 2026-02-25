package dns

import (
	"testing"

	"github.com/egorlepa/netshunt/internal/shunt"
)

func TestMatcherSuffix(t *testing.T) {
	m := NewMatcher()
	m.Update([]shunt.Entry{
		{Value: "example.com"},           // bare → suffix
		{Value: "domain:google.com"},     // explicit suffix
	})

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"a.b.example.com", true},
		{"notexample.com", false},
		{"google.com", true},
		{"mail.google.com", true},
		{"oogle.com", false},
	}

	for _, tt := range tests {
		if got := m.Match(tt.domain); got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

func TestMatcherExact(t *testing.T) {
	m := NewMatcher()
	m.Update([]shunt.Entry{
		{Value: "full:example.com"},
	})

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"www.example.com", false},
		{"sub.example.com", false},
	}

	for _, tt := range tests {
		if got := m.Match(tt.domain); got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

func TestMatcherKeyword(t *testing.T) {
	m := NewMatcher()
	m.Update([]shunt.Entry{
		{Value: "keyword:tube"},
	})

	tests := []struct {
		domain string
		want   bool
	}{
		{"youtube.com", true},
		{"tubedomain.org", true},
		{"google.com", false},
	}

	for _, tt := range tests {
		if got := m.Match(tt.domain); got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

func TestMatcherRegexp(t *testing.T) {
	m := NewMatcher()
	m.Update([]shunt.Entry{
		{Value: `regexp:^.+\.google\.com$`},
	})

	tests := []struct {
		domain string
		want   bool
	}{
		{"mail.google.com", true},
		{"a.b.google.com", true},
		{"google.com", false},
		{"notgoogle.com", false},
	}

	for _, tt := range tests {
		if got := m.Match(tt.domain); got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

func TestMatcherIgnoresIPCIDR(t *testing.T) {
	m := NewMatcher()
	m.Update([]shunt.Entry{
		{Value: "1.2.3.4"},
		{Value: "10.0.0.0/8"},
		{Value: "example.com"},
	})

	if m.Match("1.2.3.4") {
		t.Error("IP should not be in matcher")
	}
	if !m.Match("example.com") {
		t.Error("domain should match")
	}
}

func TestMatcherUpdate(t *testing.T) {
	m := NewMatcher()
	m.Update([]shunt.Entry{{Value: "old.com"}})

	if !m.Match("old.com") {
		t.Error("expected old.com to match")
	}

	m.Update([]shunt.Entry{{Value: "new.com"}})

	if m.Match("old.com") {
		t.Error("old.com should no longer match after update")
	}
	if !m.Match("new.com") {
		t.Error("expected new.com to match")
	}
}

func TestMatcherStats(t *testing.T) {
	m := NewMatcher()
	m.Update([]shunt.Entry{
		{Value: "example.com"},
		{Value: "domain:google.com"},
		{Value: "full:exact.com"},
		{Value: "keyword:tube"},
		{Value: "regexp:^test"},
	})

	s, e, k, r := m.Stats()
	if s != 2 || e != 1 || k != 1 || r != 1 {
		t.Errorf("Stats() = (%d, %d, %d, %d), want (2, 1, 1, 1)", s, e, k, r)
	}
}

func TestMatcherInvalidRegexp(t *testing.T) {
	m := NewMatcher()
	m.Update([]shunt.Entry{
		{Value: "regexp:[invalid"},
		{Value: "example.com"},
	})

	// Invalid regexp should be silently skipped, other rules still work.
	if !m.Match("example.com") {
		t.Error("expected example.com to match")
	}

	_, _, _, r := m.Stats()
	if r != 0 {
		t.Errorf("expected 0 regexps, got %d", r)
	}
}
