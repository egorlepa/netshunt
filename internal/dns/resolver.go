package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Resolver resolves domain names to IP addresses using a specified DNS server.
type Resolver struct {
	Server  string // DNS server address (e.g., "127.0.0.1:53")
	Timeout time.Duration
}

// NewResolver creates a resolver that queries the given DNS server.
func NewResolver(server string) *Resolver {
	if !strings.Contains(server, ":") {
		server = server + ":53"
	}
	return &Resolver{
		Server:  server,
		Timeout: 5 * time.Second,
	}
}

// Resolve returns all A-record IPv4 addresses for a domain.
func (r *Resolver) Resolve(ctx context.Context, domain string) ([]net.IP, error) {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	msg := new(dns.Msg)
	msg.SetQuestion(domain, dns.TypeA)
	msg.RecursionDesired = true

	client := &dns.Client{Timeout: r.Timeout}
	resp, _, err := client.ExchangeContext(ctx, msg, r.Server)
	if err != nil {
		return nil, fmt.Errorf("dns query %s: %w", domain, err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns query %s: rcode %s", domain, dns.RcodeToString[resp.Rcode])
	}

	var ips []net.IP
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			if a.A != nil && !a.A.IsUnspecified() {
				ips = append(ips, a.A)
			}
		}
	}
	return ips, nil
}

// ResolveToStrings is a convenience wrapper that returns IPs as strings.
func (r *Resolver) ResolveToStrings(ctx context.Context, domain string) ([]string, error) {
	ips, err := r.Resolve(ctx, domain)
	if err != nil {
		return nil, err
	}
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result, nil
}
