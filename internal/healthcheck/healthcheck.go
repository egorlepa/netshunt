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
	// Warn marks a failure as non-critical (e.g., the inactive backup proxy
	// being unreachable shouldn't fail the overall healthcheck).
	Warn   bool
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

	// 4. Transparent proxy listening (primary + optional backup)
	results = append(results, checkProxies(cfg)...)

	// 5. Proxy connectivity (route a test request through the proxy via OUTPUT redirect)
	results = append(results, checkProxiesConnectivity(ctx, cfg)...)

	// 6. IPSet v4
	results = append(results, checkIPSet4(ctx, cfg))

	// 7. IPTables v4
	results = append(results, checkIPTables4(ctx, cfg))

	// 10. Shunts
	results = append(results, checkShunts(shunts))

	return results
}

// ProbeDomain resolves a domain (A) and checks if the resolved IPs are in the ipset.
func ProbeDomain(ctx context.Context, cfg *config.Config, domain string) (*ProbeResult, error) {
	resolver := dns.NewResolver("127.0.0.1:53")
	ips, err := resolver.ResolveToStrings(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", domain, err)
	}

	ipset := netfilter.NewIPSet(cfg.IPSet.TableName)
	allEntries, _ := ipset.List(ctx)

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

// proxyTargets returns the proxy ports to probe with display labels.
// The currently active port is marked as active=true.
func proxyTargets(cfg *config.Config) []struct {
	label  string
	port   int
	active bool
} {
	active := cfg.Routing.ActivePort()
	targets := []struct {
		label  string
		port   int
		active bool
	}{
		{"primary", cfg.Routing.LocalPort, cfg.Routing.LocalPort == active},
	}
	if cfg.Routing.BackupPort > 0 {
		targets = append(targets, struct {
			label  string
			port   int
			active bool
		}{"backup", cfg.Routing.BackupPort, cfg.Routing.BackupPort == active})
	}
	return targets
}

func checkProxies(cfg *config.Config) []Result {
	var out []Result
	for _, t := range proxyTargets(cfg) {
		out = append(out, checkProxy(t.label, t.port, t.active))
	}
	return out
}

func checkProxy(label string, port int, active bool) Result {
	suffix := ""
	if active {
		suffix = " (active)"
	}
	r := Result{Name: fmt.Sprintf("proxy %s%s", label, suffix)}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		r.Detail = fmt.Sprintf("nothing listening on %s", addr)
		r.Warn = !active
		return r
	}
	_ = conn.Close()
	r.Passed = true
	r.Detail = fmt.Sprintf("listening on %s", addr)
	return r
}

func checkProxiesConnectivity(ctx context.Context, cfg *config.Config) []Result {
	var out []Result
	for _, t := range proxyTargets(cfg) {
		out = append(out, checkProxyConnectivity(ctx, t.label, t.port, t.active))
	}
	return out
}

func checkProxyConnectivity(ctx context.Context, label string, proxyPort int, active bool) Result {
	suffix := ""
	if active {
		suffix = " (active)"
	}
	r := Result{Name: fmt.Sprintf("proxy %s connectivity%s", label, suffix)}
	port := fmt.Sprintf("%d", proxyPort)

	const testHost = "connectivitycheck.gstatic.com"
	ips, err := net.DefaultResolver.LookupHost(ctx, testHost)
	if err != nil || len(ips) == 0 {
		r.Detail = "cannot resolve test host"
		r.Warn = !active
		return r
	}
	testIP := ips[0]

	// Temporary OUTPUT rule so the transparent proxy sees SO_ORIGINAL_DST.
	ipt := netfilter.NewIPTables()
	rule := []string{
		"OUTPUT", "-d", testIP, "-p", "tcp", "--dport", "80",
		"-j", "REDIRECT", "--to-port", port,
	}
	if err := ipt.AppendRule(ctx, "nat", rule...); err != nil {
		r.Detail = fmt.Sprintf("cannot add test rule: %v", err)
		r.Warn = !active
		return r
	}
	defer func() { _ = ipt.DeleteRule(ctx, "nat", rule...) }()

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	url := fmt.Sprintf("http://%s/generate_204", testIP)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Host = testHost
	resp, err := client.Do(req)
	if err != nil {
		r.Detail = fmt.Sprintf("proxy not forwarding: %v", err)
		r.Warn = !active
		return r
	}
	_ = resp.Body.Close()
	r.Passed = true
	r.Detail = fmt.Sprintf("HTTP %d via proxy", resp.StatusCode)
	return r
}

func checkIPSet4(ctx context.Context, cfg *config.Config) Result {
	r := Result{Name: "ipset"}
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

func checkIPTables4(ctx context.Context, cfg *config.Config) Result {
	r := Result{Name: "iptables"}
	ipt := netfilter.NewIPTables()

	port := fmt.Sprintf("%d", cfg.Routing.ActivePort())
	ipsetName := cfg.IPSet.TableName
	ifaces := cfg.Network.InterceptInterfaces()

	var missing []string

	if exists, _ := ipt.ChainExists(ctx, "nat", "NSHUNT"); !exists {
		missing = append(missing, "NSHUNT chain")
	}

	if !ipt.RuleExists(ctx, "nat", "NSHUNT", "-p", "tcp",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "REDIRECT", "--to-port", port) {
		missing = append(missing, "tcp redirect")
	}

	if len(ifaces) == 0 {
		if !ipt.RuleExists(ctx, "nat", "PREROUTING", "-j", "NSHUNT") {
			missing = append(missing, "prerouting jump")
		}
	} else {
		for _, iface := range ifaces {
			if !ipt.RuleExists(ctx, "nat", "PREROUTING", "-i", iface, "-j", "NSHUNT") {
				missing = append(missing, "prerouting jump ("+iface+")")
			}
		}
	}

	for _, iface := range cfg.Network.DNSInterfaces() {
		if !ipt.RuleExists(ctx, "nat", "PREROUTING",
			"-i", iface, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to", "127.0.0.1") {
			missing = append(missing, "dns dnat ("+iface+")")
		}
	}

	// UDP: mangle TPROXY rules.
	if exists, _ := ipt.ChainExists(ctx, "mangle", "NSHUNT_UDP"); !exists {
		missing = append(missing, "NSHUNT_UDP chain")
	} else if !ipt.RuleExists(ctx, "mangle", "NSHUNT_UDP", "-p", "udp",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "TPROXY", "--on-port", port, "--tproxy-mark", "0x1/0x1") {
		missing = append(missing, "udp tproxy")
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
