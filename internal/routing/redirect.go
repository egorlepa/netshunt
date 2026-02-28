package routing

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/deploy"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/platform"
)

const (
	redirectChainName      = "NSHUNT"
	redirectUDPChainName   = "NSHUNT_UDP"
	redirect6ChainName     = "NSHUNT6"
	redirect6UDPChainName  = "NSHUNT6_UDP"
	fwmark                 = "0x1"
	routeTable             = "100"
)

// Redirect implements Mode using NAT REDIRECT (TCP) and TPROXY (UDP)
// to a local transparent proxy port.
//
// This works with any transparent proxy that listens on a local port:
// ss-redir (-u), xray (dokodemo-door), sing-box, etc.
//
// Traffic flow:
//  1. DNS query resolved → IP added to ipset by DNS forwarder
//  2. TCP: iptables/ip6tables PREROUTING (nat) redirects to cfg.Routing.LocalPort
//  3. UDP: iptables/ip6tables PREROUTING (mangle) TPROXY to cfg.Routing.LocalPort
//  4. Transparent proxy forwards traffic through the tunnel
type Redirect struct {
	cfg    *config.Config
	ipt    *netfilter.IPTables
	ipt6   *netfilter.IPTables
	logger *slog.Logger
}

// NewRedirect creates a Redirect traffic mode handler.
func NewRedirect(cfg *config.Config, logger *slog.Logger) *Redirect {
	return &Redirect{
		cfg:    cfg,
		ipt:    netfilter.NewIPTables(),
		ipt6:   netfilter.NewIP6Tables(),
		logger: logger,
	}
}

func (r *Redirect) Name() string { return "redirect" }

// SetupRules creates iptables/ip6tables rules for TCP (NAT REDIRECT) and UDP (TPROXY).
func (r *Redirect) SetupRules(ctx context.Context) error {
	ipsetName := r.cfg.IPSet.TableName
	ipset6Name := ipsetName + "6"
	port := fmt.Sprintf("%d", r.cfg.Routing.LocalPort)
	iface := r.cfg.Network.EntwareInterface

	excluded4, excluded6 := classifyNetworks(r.cfg.ExcludedNetworks)

	r.logger.Info("setting up redirect rules",
		"ipset", ipsetName, "ipset6", ipset6Name, "port", port, "interface", iface)

	// ── IPv4 ─────────────────────────────────────────────────────────

	// TCP: NAT REDIRECT.
	if err := r.ipt.CreateChain(ctx, "nat", redirectChainName); err != nil {
		return fmt.Errorf("create tcp chain: %w", err)
	}

	for _, n := range excluded4 {
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

	if iface != "" {
		if err := r.ipt.AppendRule(ctx, "nat", "PREROUTING", "-i", iface, "-j", redirectChainName); err != nil {
			return fmt.Errorf("tcp prerouting jump: %w", err)
		}
	} else {
		if err := r.ipt.AppendRule(ctx, "nat", "PREROUTING", "-j", redirectChainName); err != nil {
			return fmt.Errorf("tcp prerouting jump: %w", err)
		}
	}

	// UDP: TPROXY via mangle table (best-effort).
	if err := r.setupUDPTproxy(ctx, r.ipt, redirectUDPChainName, ipsetName, port, iface, excluded4, "ip"); err != nil {
		r.logger.Warn("IPv4 UDP TPROXY not available, only TCP will be proxied", "error", err)
	}

	// DNS DNAT (IPv4).
	dnsIface := iface
	if dnsIface == "" {
		dnsIface = "br0"
	}
	if err := r.ipt.AppendRule(ctx, "nat", "PREROUTING",
		"-i", dnsIface, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to", "127.0.0.1"); err != nil {
		r.logger.Warn("dns dnat udp rule failed", "error", err)
	}
	if err := r.ipt.AppendRule(ctx, "nat", "PREROUTING",
		"-i", dnsIface, "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to", "127.0.0.1"); err != nil {
		r.logger.Warn("dns dnat tcp rule failed", "error", err)
	}

	// ── IPv6 (opt-in, best-effort — graceful degradation if ip6table_nat is missing) ──

	if r.cfg.IPv6 {
		if err := r.setupIPv6Rules(ctx, ipset6Name, port, iface, dnsIface, excluded6); err != nil {
			r.logger.Warn("IPv6 rules not available, only IPv4 traffic will be proxied", "error", err)
		}
	}

	return nil
}

// setupIPv6Rules sets up ip6tables rules mirroring the IPv4 setup.
func (r *Redirect) setupIPv6Rules(ctx context.Context, ipset6Name, port, iface, dnsIface string, excluded6 []string) error {
	// TCP: NAT REDIRECT via ip6tables.
	if err := r.ipt6.CreateChain(ctx, "nat", redirect6ChainName); err != nil {
		return fmt.Errorf("create ipv6 tcp chain: %w", err)
	}

	for _, n := range excluded6 {
		if err := r.ipt6.AppendRule(ctx, "nat", redirect6ChainName, "-d", n, "-j", "RETURN"); err != nil {
			_ = r.ipt6.DeleteChain(ctx, "nat", redirect6ChainName)
			return fmt.Errorf("ipv6 tcp exclude network %s: %w", n, err)
		}
	}

	if err := r.ipt6.AppendRule(ctx, "nat",
		redirect6ChainName, "-p", "tcp",
		"-m", "set", "--match-set", ipset6Name, "dst",
		"-j", "REDIRECT", "--to-port", port,
	); err != nil {
		_ = r.ipt6.DeleteChain(ctx, "nat", redirect6ChainName)
		return fmt.Errorf("ipv6 tcp redirect rule: %w", err)
	}

	if iface != "" {
		if err := r.ipt6.AppendRule(ctx, "nat", "PREROUTING", "-i", iface, "-j", redirect6ChainName); err != nil {
			_ = r.ipt6.DeleteChain(ctx, "nat", redirect6ChainName)
			return fmt.Errorf("ipv6 tcp prerouting jump: %w", err)
		}
	} else {
		if err := r.ipt6.AppendRule(ctx, "nat", "PREROUTING", "-j", redirect6ChainName); err != nil {
			_ = r.ipt6.DeleteChain(ctx, "nat", redirect6ChainName)
			return fmt.Errorf("ipv6 tcp prerouting jump: %w", err)
		}
	}

	// UDP: TPROXY via ip6tables mangle.
	if err := r.setupUDPTproxy(ctx, r.ipt6, redirect6UDPChainName, ipset6Name, port, iface, excluded6, "ip -6"); err != nil {
		r.logger.Warn("IPv6 UDP TPROXY not available", "error", err)
	}

	// DNS DNAT (IPv6).
	if err := r.ipt6.AppendRule(ctx, "nat", "PREROUTING",
		"-i", dnsIface, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to", "[::1]"); err != nil {
		r.logger.Warn("ipv6 dns dnat udp rule failed", "error", err)
	}
	if err := r.ipt6.AppendRule(ctx, "nat", "PREROUTING",
		"-i", dnsIface, "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to", "[::1]"); err != nil {
		r.logger.Warn("ipv6 dns dnat tcp rule failed", "error", err)
	}

	return nil
}

// setupUDPTproxy sets up TPROXY rules for UDP traffic using the given
// iptables instance and chain name. ipCmd is "ip" for IPv4 or "ip -6" for IPv6.
func (r *Redirect) setupUDPTproxy(ctx context.Context, ipt *netfilter.IPTables, chainName, ipsetName, port, iface string, excluded []string, ipCmd string) error {
	deploy.EnsureTproxyModule(ctx)

	if err := ipt.CreateChain(ctx, "mangle", chainName); err != nil {
		return fmt.Errorf("create udp chain: %w", err)
	}

	for _, n := range excluded {
		if err := ipt.AppendRule(ctx, "mangle", chainName, "-d", n, "-j", "RETURN"); err != nil {
			_ = ipt.DeleteChain(ctx, "mangle", chainName)
			return fmt.Errorf("udp exclude network %s: %w", n, err)
		}
	}

	if err := ipt.AppendRule(ctx, "mangle",
		chainName, "-p", "udp",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "TPROXY", "--on-port", port, "--tproxy-mark", fwmark+"/"+fwmark,
	); err != nil {
		_ = ipt.DeleteChain(ctx, "mangle", chainName)
		return fmt.Errorf("tproxy target not supported: %w", err)
	}

	if iface != "" {
		if err := ipt.AppendRule(ctx, "mangle", "PREROUTING", "-i", iface, "-j", chainName); err != nil {
			_ = ipt.DeleteChain(ctx, "mangle", chainName)
			return fmt.Errorf("udp prerouting jump: %w", err)
		}
	} else {
		if err := ipt.AppendRule(ctx, "mangle", "PREROUTING", "-j", chainName); err != nil {
			_ = ipt.DeleteChain(ctx, "mangle", chainName)
			return fmt.Errorf("udp prerouting jump: %w", err)
		}
	}

	// Policy routing for TPROXY-marked packets.
	if ipCmd == "ip -6" {
		if err := platform.RunSilent(ctx, "ip", "-6", "rule", "add", "fwmark", fwmark, "table", routeTable); err != nil {
			r.logger.Warn("ip -6 rule add failed (may already exist)", "error", err)
		}
		if err := platform.RunSilent(ctx, "ip", "-6", "route", "replace", "local", "::/0", "dev", "lo", "table", routeTable); err != nil {
			return fmt.Errorf("ip -6 route replace: %w", err)
		}
	} else {
		if err := platform.RunSilent(ctx, "ip", "rule", "add", "fwmark", fwmark, "table", routeTable); err != nil {
			r.logger.Warn("ip rule add failed (may already exist)", "error", err)
		}
		if err := platform.RunSilent(ctx, "ip", "route", "replace", "local", "0/0", "dev", "lo", "table", routeTable); err != nil {
			return fmt.Errorf("ip route replace: %w", err)
		}
	}

	return nil
}

// TeardownRules removes TCP/UDP redirect chains, policy routing, and DNS DNAT rules
// for both IPv4 and IPv6.
func (r *Redirect) TeardownRules(ctx context.Context) error {
	r.logger.Info("tearing down redirect rules")

	iface := r.cfg.Network.EntwareInterface
	dnsIface := iface
	if dnsIface == "" {
		dnsIface = "br0"
	}

	// ── IPv4 ──

	// TCP: nat table.
	_ = r.ipt.RemoveJumpRules(ctx, "nat", "PREROUTING", redirectChainName)
	_ = r.ipt.DeleteChain(ctx, "nat", redirectChainName)

	// UDP: mangle table.
	_ = r.ipt.RemoveJumpRules(ctx, "mangle", "PREROUTING", redirectUDPChainName)
	_ = r.ipt.DeleteChain(ctx, "mangle", redirectUDPChainName)

	// Policy routing for TPROXY (IPv4).
	_ = platform.RunSilent(ctx, "ip", "rule", "del", "fwmark", fwmark, "table", routeTable)
	_ = platform.RunSilent(ctx, "ip", "route", "del", "local", "0/0", "table", routeTable)

	// DNS DNAT (IPv4).
	_ = r.ipt.DeleteRule(ctx, "nat", "PREROUTING",
		"-i", dnsIface, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to", "127.0.0.1")
	_ = r.ipt.DeleteRule(ctx, "nat", "PREROUTING",
		"-i", dnsIface, "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to", "127.0.0.1")

	// ── IPv6 ──

	// TCP: nat table.
	_ = r.ipt6.RemoveJumpRules(ctx, "nat", "PREROUTING", redirect6ChainName)
	_ = r.ipt6.DeleteChain(ctx, "nat", redirect6ChainName)

	// UDP: mangle table.
	_ = r.ipt6.RemoveJumpRules(ctx, "mangle", "PREROUTING", redirect6UDPChainName)
	_ = r.ipt6.DeleteChain(ctx, "mangle", redirect6UDPChainName)

	// Policy routing for TPROXY (IPv6).
	_ = platform.RunSilent(ctx, "ip", "-6", "rule", "del", "fwmark", fwmark, "table", routeTable)
	_ = platform.RunSilent(ctx, "ip", "-6", "route", "del", "local", "::/0", "table", routeTable)

	// DNS DNAT (IPv6).
	_ = r.ipt6.DeleteRule(ctx, "nat", "PREROUTING",
		"-i", dnsIface, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to", "[::1]")
	_ = r.ipt6.DeleteRule(ctx, "nat", "PREROUTING",
		"-i", dnsIface, "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to", "[::1]")

	return nil
}

// IsActive checks if something is listening on the configured local port.
func (r *Redirect) IsActive(ctx context.Context) (bool, error) {
	port := fmt.Sprintf(":%d", r.cfg.Routing.LocalPort)
	ok, err := netfilter.CheckListeningPort(ctx, port)
	if err != nil {
		return false, nil
	}
	return ok, nil
}

// classifyNetworks splits a list of CIDRs into IPv4 and IPv6 groups.
func classifyNetworks(networks []string) (v4, v6 []string) {
	for _, n := range networks {
		_, cidr, err := net.ParseCIDR(n)
		if err != nil {
			continue
		}
		if cidr.IP.To4() != nil {
			v4 = append(v4, n)
		} else {
			v6 = append(v6, n)
		}
	}
	return
}
