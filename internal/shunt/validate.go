package shunt

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// InvalidEntryError reports an entry value that cannot be applied.
type InvalidEntryError struct {
	Value  string
	Reason string
}

func (e *InvalidEntryError) Error() string {
	return fmt.Sprintf("invalid entry %q: %s", e.Value, e.Reason)
}

func invalid(value, format string, args ...any) error {
	return &InvalidEntryError{Value: value, Reason: fmt.Sprintf(format, args...)}
}

// Validate reports whether value, after the normalisation the store applies
// on add, is an entry netshunt can apply: an IPv4 address or CIDR, a domain
// (suffix or full) made of DNS-safe labels, a non-empty DNS-safe keyword, or
// a regexp that compiles (RE2). IPv6 addresses and networks are rejected:
// netshunt routes only IPv4.
func Validate(value string) error {
	v := normalizeEntry(value)
	if v == "" {
		return invalid(value, "empty value")
	}
	e := Entry{Value: v}
	switch e.Type() {
	case EntryIP:
		if net.ParseIP(v).To4() == nil {
			return invalid(value, "IPv6 is not supported, only IPv4 addresses")
		}
	case EntryCIDR:
		_, n, _ := net.ParseCIDR(v)
		if n.IP.To4() == nil {
			return invalid(value, "IPv6 is not supported, only IPv4 networks")
		}
	case EntryDomainRegexp:
		pat := e.DomainValue()
		if pat == "" {
			return invalid(value, "empty regexp")
		}
		if _, err := regexp.Compile(pat); err != nil {
			return invalid(value, "regexp does not compile: %v", err)
		}
	case EntryDomainKeyword:
		kw := strings.ToLower(e.DomainValue())
		if kw == "" {
			return invalid(value, "empty keyword")
		}
		if c, ok := firstUnsafe(kw); ok {
			return invalid(value, "character %q is not allowed in a domain", c)
		}
	default: // suffix, full
		return validateDomain(value, e.DomainValue())
	}
	return nil
}

func validateDomain(value, d string) error {
	if d == "" {
		return invalid(value, "empty domain")
	}
	if c, ok := firstUnsafe(d); ok {
		return invalid(value, "character %q is not allowed in a domain", c)
	}
	if len(d) > 253 {
		return invalid(value, "domain longer than 253 characters")
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" {
			return invalid(value, "empty label (leading, trailing or double dot)")
		}
		if len(label) > 63 {
			return invalid(value, "label longer than 63 characters")
		}
	}
	return nil
}

// firstUnsafe returns the first character of s outside [a-z0-9._-].
func firstUnsafe(s string) (rune, bool) {
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
		default:
			return c, true
		}
	}
	return 0, false
}

// Valid reports whether the entry can be applied (see Validate).
func (e Entry) Valid() bool { return Validate(e.Value) == nil }
