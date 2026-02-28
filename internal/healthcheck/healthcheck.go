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

	// 6. IPSet v4
	results = append(results, checkIPSet4(ctx, cfg))

	// 7. IPTables v4
	results = append(results, checkIPTables4(ctx, cfg))

	if cfg.IPv6 {
		// 8. IPSet v6
		results = append(results, checkIPSet6(ctx, cfg))

		// 9. IPTables v6
		results = append(results, checkIPTables6(ctx, cfg))
	}

	// 10. Shunts
	results = append(results, checkShunts(shunts))

	return results
}

// ProbeDomain resolves a domain (A + AAAA) and checks if the resolved IPs are
// in the appropriate ipset (v4 or v6).
func ProbeDomain(ctx context.Context, cfg *config.Config, domain string) (*ProbeResult, error) {
	resolver := dns.NewResolver("127.0.0.1:53")
	ips, err := resolver.ResolveToStrings(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", domain, err)
	}

	// Collect entries from ipset tables.
	ipset4 := netfilter.NewIPSet(cfg.IPSet.TableName)
	allEntries, _ := ipset4.List(ctx)
	if cfg.IPv6 {
		ipset6 := netfilter.NewIPSet6(cfg.IPSet.TableName + "6")
		entries6, _ := ipset6.List(ctx)
		allEntries = append(allEntries, entries6...)
	}

	// Parse ipset entries into nets for CIDR containment checks.
	// Entries may include metadata like "1.2.3.4 timeout 12345", so extract just the IP/CIDR.
	var nets []*net.IPNet
	ipMap := make(map[string]bool)
	for _, e := range allEntries {
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

func checkIPSet4(ctx context.Context, cfg *config.Config) Result {
	r := Result{Name: "ipset v4"}
	ipset := netfilter.NewIPSet(cfg.IPSet.TableName)
	count, err := ipset.Count(ctx)
	if err != nil {
		r.Detail = fmt.Sprintf("table %q: %v", cfg.IPSet.TableName, err)
		return r
	}
	r.Passed = true
	r.Detail = fmt.Sprintf("%d entries in %s", count, cfg.IPSet.TableName)
	return r
}

func checkIPSet6(ctx context.Context, cfg *config.Config) Result {
	name := cfg.IPSet.TableName + "6"
	r := Result{Name: "ipset v6"}
	ipset := netfilter.NewIPSet6(name)
	count, err := ipset.Count(ctx)
	if err != nil {
		r.Detail = fmt.Sprintf("table %q: %v", name, err)
		return r
	}
	r.Passed = true
	r.Detail = fmt.Sprintf("%d entries in %s", count, name)
	return r
}

func checkIPTables4(ctx context.Context, cfg *config.Config) Result {
	r := Result{Name: "iptables v4"}
	ipt := netfilter.NewIPTables()

	port := fmt.Sprintf("%d", cfg.Routing.LocalPort)
	ipsetName := cfg.IPSet.TableName
	iface := cfg.Network.EntwareInterface

	var missing []string

	if exists, _ := ipt.ChainExists(ctx, "nat", "NSHUNT"); !exists {
		missing = append(missing, "NSHUNT chain")
	}

	if !ipt.RuleExists(ctx, "nat", "NSHUNT", "-p", "tcp",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "REDIRECT", "--to-port", port) {
		missing = append(missing, "tcp redirect")
	}

	if iface != "" {
		if !ipt.RuleExists(ctx, "nat", "PREROUTING", "-i", iface, "-j", "NSHUNT") {
			missing = append(missing, "prerouting jump")
		}
	} else {
		if !ipt.RuleExists(ctx, "nat", "PREROUTING", "-j", "NSHUNT") {
			missing = append(missing, "prerouting jump")
		}
	}

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

func checkIPTables6(ctx context.Context, cfg *config.Config) Result {
	r := Result{Name: "iptables v6"}
	ipt6 := netfilter.NewIP6Tables()

	port := fmt.Sprintf("%d", cfg.Routing.LocalPort)
	ipset6Name := cfg.IPSet.TableName + "6"
	iface := cfg.Network.EntwareInterface

	dnsIface := iface
	if dnsIface == "" {
		dnsIface = "br0"
	}

	var missing []string

	if exists, _ := ipt6.ChainExists(ctx, "nat", "NSHUNT6"); !exists {
		missing = append(missing, "NSHUNT6 chain")
	}

	if !ipt6.RuleExists(ctx, "nat", "NSHUNT6", "-p", "tcp",
		"-m", "set", "--match-set", ipset6Name, "dst",
		"-j", "REDIRECT", "--to-port", port) {
		missing = append(missing, "tcp redirect")
	}

	if !ipt6.RuleExists(ctx, "nat", "PREROUTING",
		"-i", dnsIface, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to", "[::1]") {
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
