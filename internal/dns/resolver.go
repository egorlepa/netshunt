package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
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
	return r.resolve(ctx, domain, dns.TypeA)
}

func (r *Resolver) resolve(ctx context.Context, domain string, qtype uint16) ([]net.IP, error) {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	msg := dns.NewMsg(domain, qtype)
	if msg == nil {
		return nil, fmt.Errorf("dns: failed to create query for %s", domain)
	}

	client := dns.NewClient()
	client.ReadTimeout = r.Timeout
	client.WriteTimeout = r.Timeout

	resp, _, err := client.Exchange(ctx, msg, "udp", r.Server)
	if err != nil {
		return nil, fmt.Errorf("dns query %s: %w", domain, err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns query %s: rcode %s", domain, dns.RcodeToString[resp.Rcode])
	}

	var ips []net.IP
	for _, ans := range resp.Answer {
		switch a := ans.(type) {
		case *dns.A:
			ip := a.Addr
			if ip.IsValid() && !ip.IsUnspecified() {
				ips = append(ips, ip.AsSlice())
			}
		}
	}
	return ips, nil
}

// ResolveToStrings resolves A records and returns IPs as strings.
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
