package routing

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/deploy"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/platform"
)

const (
	redirectChainName    = "NSHUNT"
	redirectUDPChainName = "NSHUNT_UDP"
	fwmark               = "0x1"
	routeTable           = "100"
	// rulePref is the policy-rule priority. It must stay clear of the
	// priorities Keenetic NDM manages itself (it owns 100/101 among others
	// and deletes by number when it rebuilds them), and below main (32766)
	// so marked packets hit table 100 first.
	rulePref = "32000"
)

// Redirect implements Mode using NAT REDIRECT (TCP) and TPROXY (UDP)
// to a local transparent proxy port.
//
// This works with any transparent proxy that listens on a local port:
// ss-redir (-u), xray (dokodemo-door), sing-box, etc.
//
// Traffic flow:
//  1. DNS query resolved → IP added to ipset by DNS forwarder
//  2. TCP: iptables PREROUTING (nat) redirects to cfg.Routing.ActivePort()
//  3. UDP: iptables PREROUTING (mangle) TPROXY to cfg.Routing.ActivePort()
//  4. Transparent proxy forwards traffic through the tunnel
type Redirect struct {
	cfg    *config.Config
	ipt    *netfilter.IPTables
	logger *slog.Logger
}

// NewRedirect creates a Redirect traffic mode handler.
func NewRedirect(cfg *config.Config, logger *slog.Logger) *Redirect {
	return &Redirect{
		cfg:    cfg,
		ipt:    netfilter.NewIPTables(),
		logger: logger,
	}
}

func (r *Redirect) Name() string { return "redirect" }

// SetupRules creates iptables rules for TCP (NAT REDIRECT) and UDP (TPROXY).
func (r *Redirect) SetupRules(ctx context.Context) error {
	ipsetName := r.cfg.IPSet.TableName
	port := fmt.Sprintf("%d", r.cfg.Routing.ActivePort())
	ifaces := r.cfg.Network.InterceptInterfaces()

	excluded := filterIPv4Networks(r.cfg.ExcludedNetworks)

	r.logger.Info("setting up redirect rules",
		"ipset", ipsetName, "port", port, "interfaces", ifaces)

	// TCP: NAT REDIRECT.
	if err := r.ipt.CreateChain(ctx, "nat", redirectChainName); err != nil {
		return fmt.Errorf("create tcp chain: %w", err)
	}

	for _, n := range excluded {
		if err := r.ipt.AppendRule(ctx, "nat", redirectChainName, "-d", n, "-j", "RETURN"); err != nil {
			return fmt.Errorf("tcp exclude network %s: %w", n, err)
		}
	}

	if err := r.ipt.AppendRule(ctx, "nat",
		redirectChainName, "-p", "tcp",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "REDIRECT", "--to-port", port,
	); err != nil {
		return fmt.Errorf("tcp redirect rule: %w", err)
	}

	if len(ifaces) == 0 {
		if err := r.ipt.AppendRule(ctx, "nat", "PREROUTING", "-j", redirectChainName); err != nil {
			return fmt.Errorf("tcp prerouting jump: %w", err)
		}
	} else {
		for _, iface := range ifaces {
			if err := r.ipt.AppendRule(ctx, "nat", "PREROUTING", "-i", iface, "-j", redirectChainName); err != nil {
				return fmt.Errorf("tcp prerouting jump (%s): %w", iface, err)
			}
		}
	}

	// UDP: TPROXY via mangle table (best-effort).
	if err := r.setupUDPTproxy(ctx, ipsetName, port, ifaces, excluded); err != nil {
		r.logger.Warn("UDP TPROXY not available, only TCP will be proxied", "error", err)
	}

	// DNS interception. REDIRECT rewrites the destination to the primary
	// address of the ingress interface (192.168.1.1 on br0, the TUN address
	// on awg0), which the router's INPUT chain already accepts. A DNAT to
	// 127.0.0.1 does not work here: packets that arrive on br0 with a
	// loopback destination are dropped before they reach the forwarder, so
	// clients with a hard-coded resolver got no answer at all.
	for _, iface := range r.cfg.Network.DNSInterfaces() {
		for _, proto := range []string{"udp", "tcp"} {
			if err := r.ipt.AppendRule(ctx, "nat", DNSRedirectRule(iface, proto)...); err != nil {
				r.logger.Warn("dns redirect rule failed", "iface", iface, "proto", proto, "error", err)
			}
		}
	}

	return nil
}

// setupUDPTproxy sets up TPROXY rules for UDP traffic.
func (r *Redirect) setupUDPTproxy(ctx context.Context, ipsetName, port string, ifaces []string, excluded []string) error {
	deploy.EnsureTproxyModule(ctx)

	if err := r.ipt.CreateChain(ctx, "mangle", redirectUDPChainName); err != nil {
		return fmt.Errorf("create udp chain: %w", err)
	}

	for _, n := range excluded {
		if err := r.ipt.AppendRule(ctx, "mangle", redirectUDPChainName, "-d", n, "-j", "RETURN"); err != nil {
			_ = r.ipt.DeleteChain(ctx, "mangle", redirectUDPChainName)
			return fmt.Errorf("udp exclude network %s: %w", n, err)
		}
	}

	if err := r.ipt.AppendRule(ctx, "mangle",
		redirectUDPChainName, "-p", "udp",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "TPROXY", "--on-port", port, "--tproxy-mark", fwmark+"/"+fwmark,
	); err != nil {
		_ = r.ipt.DeleteChain(ctx, "mangle", redirectUDPChainName)
		return fmt.Errorf("tproxy target not supported: %w", err)
	}

	if len(ifaces) == 0 {
		if err := r.ipt.AppendRule(ctx, "mangle", "PREROUTING", "-j", redirectUDPChainName); err != nil {
			_ = r.ipt.DeleteChain(ctx, "mangle", redirectUDPChainName)
			return fmt.Errorf("udp prerouting jump: %w", err)
		}
	} else {
		for _, iface := range ifaces {
			if err := r.ipt.AppendRule(ctx, "mangle", "PREROUTING", "-i", iface, "-j", redirectUDPChainName); err != nil {
				_ = r.ipt.DeleteChain(ctx, "mangle", redirectUDPChainName)
				return fmt.Errorf("udp prerouting jump (%s): %w", iface, err)
			}
		}
	}

	// Policy routing for TPROXY-marked packets. "ip rule add" is not
	// idempotent and this path also runs from the NDM netfilter hook without
	// a teardown, so check first and pin the priority so teardown can
	// remove exactly this rule.
	if !r.policyRuleExists(ctx) {
		if err := platform.RunSilent(ctx, "ip", "rule", "add", "pref", rulePref, "fwmark", fwmark, "table", routeTable); err != nil {
			return fmt.Errorf("ip rule add: %w", err)
		}
	}
	if err := platform.RunSilent(ctx, "ip", "route", "replace", "local", "0/0", "dev", "lo", "table", routeTable); err != nil {
		return fmt.Errorf("ip route replace: %w", err)
	}

	return nil
}

// policyRuleExists reports whether the fwmark policy rule is already
// installed at rulePref. "ip rule show" prints one rule per line as
// "<pref>:\tfrom all fwmark 0x1 lookup 100".
func (r *Redirect) policyRuleExists(ctx context.Context) bool {
	out, err := platform.Run(ctx, "ip", "rule", "show")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, rulePref+":") &&
			strings.Contains(line, "fwmark "+fwmark+" ") &&
			strings.Contains(line, "lookup "+routeTable) {
			return true
		}
	}
	return false
}

// TeardownRules removes TCP/UDP redirect chains, policy routing, and DNS DNAT rules.
func (r *Redirect) TeardownRules(ctx context.Context) error {
	r.logger.Info("tearing down redirect rules")

	// TCP: nat table.
	_ = r.ipt.RemoveJumpRules(ctx, "nat", "PREROUTING", redirectChainName)
	_ = r.ipt.DeleteChain(ctx, "nat", redirectChainName)

	// UDP: mangle table.
	_ = r.ipt.RemoveJumpRules(ctx, "mangle", "PREROUTING", redirectUDPChainName)
	_ = r.ipt.DeleteChain(ctx, "mangle", redirectUDPChainName)

	// Policy routing for TPROXY.
	_ = platform.RunSilent(ctx, "ip", "rule", "del", "pref", rulePref, "fwmark", fwmark, "table", routeTable)
	_ = platform.RunSilent(ctx, "ip", "route", "del", "local", "0/0", "table", routeTable)

	// DNS interception.
	for _, iface := range r.cfg.Network.DNSInterfaces() {
		for _, proto := range []string{"udp", "tcp"} {
			_ = r.ipt.DeleteRule(ctx, "nat", DNSRedirectRule(iface, proto)...)
		}
	}

	return nil
}

// IsActive checks if something is listening on the configured local port.
func (r *Redirect) IsActive(ctx context.Context) (bool, error) {
	port := fmt.Sprintf(":%d", r.cfg.Routing.ActivePort())
	ok, err := netfilter.CheckListeningPort(ctx, port)
	if err != nil {
		return false, nil
	}
	return ok, nil
}

// filterIPv4Networks returns only the IPv4 CIDRs from the input.
// Validation at the form layer rejects v6 entries, but legacy configs may
// still contain them — skip silently to avoid breaking startup.
func filterIPv4Networks(networks []string) []string {
	var out []string
	for _, n := range networks {
		_, cidr, err := net.ParseCIDR(n)
		if err != nil {
			continue
		}
		if cidr.IP.To4() != nil {
			out = append(out, n)
		}
	}
	return out
}

// DNSRedirectRule is the nat PREROUTING rule that steers port-53 traffic from
// iface to the local forwarder. Shared by setup, teardown and the healthcheck
// so all three agree on the exact rule signature.
func DNSRedirectRule(iface, proto string) []string {
	return []string{"PREROUTING", "-i", iface, "-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"}
}
