package healthcheck

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/dns"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/service"
	"github.com/egorlepa/netshunt/internal/shunt"
)

// Result represents a single health check outcome.
type Result struct {
	Name   string
	Passed bool
	Detail string
}

// ProbeResult represents the result of a domain probe.
type ProbeResult struct {
	Domain  string
	IPs     []string
	InIPSet map[string]bool // IP -> found in ipset
}

// RunChecks performs all health checks and returns the results.
func RunChecks(ctx context.Context, cfg *config.Config, shunts *shunt.Store) []Result {
	var results []Result

	// 1. dnscrypt-proxy
	results = append(results, checkService(ctx, service.DNSCrypt))

	// 2. Daemon
	results = append(results, checkService(ctx, service.Daemon))

	// 3. DNS forwarder
	results = append(results, checkForwarder(ctx, cfg))

	// 4. Transparent proxy listening
	results = append(results, checkProxy(cfg))

	// 5. Internet connectivity
	results = append(results, checkConnectivity(ctx))

	// 7. IPSet table
	results = append(results, checkIPSet(ctx, cfg))

	// 8. IPTables rules
	results = append(results, checkIPTables(ctx, cfg))

	// 9. Shunts
	results = append(results, checkShunts(shunts))

	return results
}

// ProbeDomain resolves a domain and checks if the resolved IPs are in the ipset.
func ProbeDomain(ctx context.Context, cfg *config.Config, domain string) (*ProbeResult, error) {
	resolver := dns.NewResolver("127.0.0.1:53")
	ips, err := resolver.ResolveToStrings(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", domain, err)
	}

	ipset := netfilter.NewIPSet(cfg.IPSet.TableName)
	entries, err := ipset.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list ipset: %w", err)
	}

	// Parse ipset entries into nets for CIDR containment checks.
	// Entries may include metadata like "1.2.3.4 timeout 12345", so extract just the IP/CIDR.
	var nets []*net.IPNet
	ipMap := make(map[string]bool)
	for _, e := range entries {
		addr := strings.Fields(e)[0]
		if _, cidr, err := net.ParseCIDR(addr); err == nil {
			nets = append(nets, cidr)
		} else {
			ipMap[addr] = true
		}
	}

	result := &ProbeResult{
		Domain:  domain,
		IPs:     ips,
		InIPSet: make(map[string]bool),
	}

	for _, ip := range ips {
		if ipMap[ip] {
			result.InIPSet[ip] = true
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed != nil {
			for _, cidr := range nets {
				if cidr.Contains(parsed) {
					result.InIPSet[ip] = true
					break
				}
			}
		}
	}

	return result, nil
}

func checkService(ctx context.Context, svc service.Service) Result {
	r := Result{Name: svc.Name}
	if !svc.IsInstalled() {
		r.Detail = "not installed"
		return r
	}
	if !svc.IsRunning(ctx) {
		r.Detail = "stopped"
		return r
	}
	r.Passed = true
	r.Detail = "running"
	return r
}

func checkProxy(cfg *config.Config) Result {
	r := Result{Name: "proxy"}
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Routing.LocalPort)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		r.Detail = fmt.Sprintf("nothing listening on %s", addr)
		return r
	}
	conn.Close()
	r.Passed = true
	r.Detail = fmt.Sprintf("listening on %s", addr)
	return r
}

func checkConnectivity(ctx context.Context) Result {
	r := Result{Name: "connectivity"}
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://connectivitycheck.gstatic.com/generate_204", nil)
	resp, err := client.Do(req)
	if err != nil {
		r.Detail = fmt.Sprintf("request failed: %v", err)
		return r
	}
	resp.Body.Close()
	r.Passed = true
	r.Detail = fmt.Sprintf("HTTP %d", resp.StatusCode)
	return r
}

func checkIPSet(ctx context.Context, cfg *config.Config) Result {
	r := Result{Name: "ipset"}
	ipset := netfilter.NewIPSet(cfg.IPSet.TableName)
	count, err := ipset.Count(ctx)
	if err != nil {
		r.Detail = fmt.Sprintf("table %q: %v", cfg.IPSet.TableName, err)
		return r
	}
	r.Passed = true
	r.Detail = fmt.Sprintf("%d entries", count)
	return r
}

func checkIPTables(ctx context.Context, cfg *config.Config) Result {
	r := Result{Name: "iptables"}
	ipt := netfilter.NewIPTables()

	port := fmt.Sprintf("%d", cfg.Routing.LocalPort)
	ipsetName := cfg.IPSet.TableName
	iface := cfg.Network.EntwareInterface

	var missing []string

	// NSHUNT chain must exist.
	if exists, _ := ipt.ChainExists(ctx, "nat", "NSHUNT"); !exists {
		missing = append(missing, "NSHUNT chain")
	}

	// TCP redirect rule inside NSHUNT.
	if !ipt.RuleExists(ctx, "nat", "NSHUNT", "-p", "tcp",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "REDIRECT", "--to-port", port) {
		missing = append(missing, "tcp redirect")
	}

	// PREROUTING → NSHUNT jump.
	if iface != "" {
		if !ipt.RuleExists(ctx, "nat", "PREROUTING", "-i", iface, "-j", "NSHUNT") {
			missing = append(missing, "prerouting jump")
		}
	} else {
		if !ipt.RuleExists(ctx, "nat", "PREROUTING", "-j", "NSHUNT") {
			missing = append(missing, "prerouting jump")
		}
	}

	// DNS DNAT rule (port 53 → local forwarder).
	dnsIface := iface
	if dnsIface == "" {
		dnsIface = "br0"
	}
	if !ipt.RuleExists(ctx, "nat", "PREROUTING",
		"-i", dnsIface, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to", "127.0.0.1") {
		missing = append(missing, "dns dnat")
	}

	if len(missing) == 0 {
		r.Passed = true
		r.Detail = "all rules present"
	} else {
		r.Detail = fmt.Sprintf("missing: %s", strings.Join(missing, ", "))
	}
	return r
}

func checkForwarder(ctx context.Context, cfg *config.Config) Result {
	r := Result{Name: "dns forwarder"}
	resolver := dns.NewResolver(cfg.DNS.ListenAddr)
	_, err := resolver.ResolveToStrings(ctx, "example.com")
	if err != nil {
		r.Detail = fmt.Sprintf("not responding on %s", cfg.DNS.ListenAddr)
		return r
	}
	r.Passed = true
	r.Detail = fmt.Sprintf("responding on %s", cfg.DNS.ListenAddr)
	return r
}

func checkShunts(shunts *shunt.Store) Result {
	r := Result{Name: "shunts"}
	list, err := shunts.List()
	if err != nil {
		r.Detail = err.Error()
		return r
	}

	enabled, entries := 0, 0
	for _, s := range list {
		if s.Enabled {
			enabled++
			entries += len(s.Entries)
		}
	}

	if enabled == 0 {
		r.Detail = "no enabled shunts"
		return r
	}

	r.Passed = true
	r.Detail = fmt.Sprintf("%d enabled, %d entries", enabled, entries)
	return r
}
