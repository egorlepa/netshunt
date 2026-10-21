package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// DefaultDNSUpstreams returns the resolvers used when dns.upstreams is empty.
func DefaultDNSUpstreams() []DNSUpstream {
	return []DNSUpstream{
		{URL: "https://8.8.8.8/dns-query", SNI: "dns.google"},
		{URL: "https://1.1.1.1/dns-query", SNI: "cloudflare-dns.com"},
		{URL: "https://9.9.9.9/dns-query", SNI: "dns.quad9.net"},
	}
}

// EffectiveUpstreams returns the configured upstreams, or the defaults when
// none are configured.
func (d DNSConfig) EffectiveUpstreams() []DNSUpstream {
	if len(d.Upstreams) == 0 {
		return DefaultDNSUpstreams()
	}
	return d.Upstreams
}

// Validate checks that u is an https URL with an IP-literal host and a
// non-empty SNI.
func (u DNSUpstream) Validate() error {
	parsed, err := url.Parse(u.URL)
	if err != nil {
		return fmt.Errorf("upstream %q: %w", u.URL, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("upstream %q: scheme must be https", u.URL)
	}
	if _, err := netip.ParseAddr(parsed.Hostname()); err != nil {
		return fmt.Errorf("upstream %q: host must be an IP address", u.URL)
	}
	if strings.TrimSpace(u.SNI) == "" {
		return fmt.Errorf("upstream %q: sni is empty", u.URL)
	}
	if strings.ContainsAny(u.SNI, " \t/:") {
		return fmt.Errorf("upstream %q: invalid sni %q", u.URL, u.SNI)
	}
	return nil
}

// ValidateUpstreams validates every upstream. An empty list is valid and
// means the defaults.
func ValidateUpstreams(ups []DNSUpstream) error {
	var errs []error
	for _, u := range ups {
		if err := u.Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ParseDNSUpstreams parses one upstream per line in the form
// "https://8.8.8.8/dns-query dns.google". Blank lines are skipped; the result
// is validated. Empty text yields nil, which means the defaults.
func ParseDNSUpstreams(text string) ([]DNSUpstream, error) {
	var ups []DNSUpstream
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		switch len(fields) {
		case 0:
			continue
		case 2:
			ups = append(ups, DNSUpstream{URL: fields[0], SNI: fields[1]})
		default:
			return nil, fmt.Errorf("upstream line %q: want \"<url> <sni>\"", strings.TrimSpace(line))
		}
	}
	if err := ValidateUpstreams(ups); err != nil {
		return nil, err
	}
	return ups, nil
}

// FormatDNSUpstreams renders upstreams in the ParseDNSUpstreams format.
func FormatDNSUpstreams(ups []DNSUpstream) string {
	lines := make([]string, len(ups))
	for i, u := range ups {
		lines[i] = u.URL + " " + u.SNI
	}
	return strings.Join(lines, "\n")
}
