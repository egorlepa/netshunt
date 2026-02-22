package healthcheck

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/dns"
	"github.com/egorlepa/netshunt/internal/group"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/platform"
	"github.com/egorlepa/netshunt/internal/routing"
	"github.com/egorlepa/netshunt/internal/service"
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
func RunChecks(ctx context.Context, cfg *config.Config, groups *group.Store) []Result {
	var results []Result

	// 1. dnsmasq
	results = append(results, checkService(ctx, service.Dnsmasq))

	// 2. dnscrypt-proxy
	results = append(results, checkService(ctx, service.DNSCrypt))

	// 3. Daemon
	results = append(results, checkService(ctx, service.Daemon))

	// 4. Routing active
	results = append(results, checkRouting(ctx, cfg))

	// 4. IPSet table
	results = append(results, checkIPSet(ctx, cfg))

	// 5. IPTables rules
	results = append(results, checkIPTables(ctx, cfg))

	// 6. Dnsmasq ipset config
	results = append(results, checkDnsmasqConfig())

	// 7. Groups
	results = append(results, checkGroups(groups))

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

func checkRouting(ctx context.Context, cfg *config.Config) Result {
	r := Result{Name: "routing"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mode := routing.New(cfg, logger)
	active, _ := mode.IsActive(ctx)

	detail := fmt.Sprintf("redirect (port %d)", cfg.Routing.LocalPort)

	if active {
		r.Passed = true
		r.Detail = detail + " — active"
	} else {
		r.Detail = detail + " — inactive"
	}
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

	chain, table := "NSHUNT", "nat"
	exists, _ := ipt.ChainExists(ctx, table, chain)
	if exists {
		r.Passed = true
		r.Detail = fmt.Sprintf("%s chain in %s table", chain, table)
	} else {
		r.Detail = fmt.Sprintf("%s chain missing in %s table", chain, table)
	}
	return r
}

func checkDnsmasqConfig() Result {
	r := Result{Name: "dnsmasq config"}
	info, err := os.Stat(platform.DnsmasqIPSetFile)
	if err != nil {
		r.Detail = "file missing"
		return r
	}
	if info.Size() == 0 {
		r.Detail = "file empty"
		return r
	}

	// Count domains in the file.
	f, err := os.Open(platform.DnsmasqIPSetFile)
	if err != nil {
		r.Detail = "cannot read file"
		return r
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "ipset=/") {
			count++
		}
	}

	r.Passed = true
	r.Detail = fmt.Sprintf("%d domains", count)
	return r
}

func checkGroups(groups *group.Store) Result {
	r := Result{Name: "groups"}
	list, err := groups.List()
	if err != nil {
		r.Detail = err.Error()
		return r
	}

	enabled, entries := 0, 0
	for _, g := range list {
		if g.Enabled {
			enabled++
			entries += len(g.Entries)
		}
	}

	if enabled == 0 {
		r.Detail = "no enabled groups"
		return r
	}

	r.Passed = true
	r.Detail = fmt.Sprintf("%d enabled, %d entries", enabled, entries)
	return r
}
