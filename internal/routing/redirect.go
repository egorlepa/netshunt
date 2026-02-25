package routing

import (
	"context"
	"fmt"
	"log/slog"

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
)

// Redirect implements Mode using NAT REDIRECT (TCP) and TPROXY (UDP)
// to a local transparent proxy port.
//
// This works with any transparent proxy that listens on a local port:
// ss-redir (-u), xray (dokodemo-door), sing-box, etc.
//
// Traffic flow:
//  1. DNS query resolved → IP added to ipset by DNS forwarder
//  2. TCP: iptables PREROUTING (nat) redirects to cfg.Routing.LocalPort
//  3. UDP: iptables PREROUTING (mangle) TPROXY to cfg.Routing.LocalPort
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
//
// TCP (nat table):
//
//	iptables -t nat -N NSHUNT
//	iptables -t nat -A NSHUNT -d <excluded_net> -j RETURN
//	iptables -t nat -A NSHUNT -p tcp -m set --match-set <ipset> dst -j REDIRECT --to-port <port>
//	iptables -t nat -A PREROUTING [-i <iface>] -j NSHUNT
//
// UDP (mangle table):
//
//	iptables -t mangle -N NSHUNT_UDP
//	iptables -t mangle -A NSHUNT_UDP -d <excluded_net> -j RETURN
//	iptables -t mangle -A NSHUNT_UDP -p udp -m set --match-set <ipset> dst -j TPROXY --on-port <port> --tproxy-mark 0x1/0x1
//	iptables -t mangle -A PREROUTING [-i <iface>] -j NSHUNT_UDP
//	ip rule add fwmark 0x1 table 100
//	ip route replace local 0/0 dev lo table 100
func (r *Redirect) SetupRules(ctx context.Context) error {
	ipsetName := r.cfg.IPSet.TableName
	port := fmt.Sprintf("%d", r.cfg.Routing.LocalPort)
	iface := r.cfg.Network.EntwareInterface

	r.logger.Info("setting up redirect iptables rules",
		"ipset", ipsetName, "port", port, "interface", iface)

	// TCP: NAT REDIRECT.
	if err := r.ipt.CreateChain(ctx, "nat", redirectChainName); err != nil {
		return fmt.Errorf("create tcp chain: %w", err)
	}

	for _, net := range r.cfg.ExcludedNetworks {
		if err := r.ipt.AppendRule(ctx, "nat", redirectChainName, "-d", net, "-j", "RETURN"); err != nil {
			return fmt.Errorf("tcp exclude network %s: %w", net, err)
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

	// UDP: TPROXY via mangle table (best-effort — requires iptables TPROXY extension).
	if err := r.setupUDPTproxy(ctx, ipsetName, port, iface); err != nil {
		r.logger.Warn("UDP TPROXY not available, only TCP will be proxied", "error", err)
	}

	// DNS DNAT: redirect all port-53 traffic from the LAN to the local forwarder.
	// Use br0 as the default interface when none is configured, to avoid redirecting
	// the router's own DNS queries.
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

	return nil
}

// setupUDPTproxy sets up TPROXY rules for UDP traffic. Returns an error if
// TPROXY is not supported (e.g. iptables built without libxt_TPROXY.so).
func (r *Redirect) setupUDPTproxy(ctx context.Context, ipsetName, port, iface string) error {
	deploy.EnsureTproxyModule(ctx)

	if err := r.ipt.CreateChain(ctx, "mangle", redirectUDPChainName); err != nil {
		return fmt.Errorf("create udp chain: %w", err)
	}

	for _, net := range r.cfg.ExcludedNetworks {
		if err := r.ipt.AppendRule(ctx, "mangle", redirectUDPChainName, "-d", net, "-j", "RETURN"); err != nil {
			// Clean up the chain we just created.
			_ = r.ipt.DeleteChain(ctx, "mangle", redirectUDPChainName)
			return fmt.Errorf("udp exclude network %s: %w", net, err)
		}
	}

	if err := r.ipt.AppendRule(ctx, "mangle",
		redirectUDPChainName, "-p", "udp",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "TPROXY", "--on-port", port, "--tproxy-mark", fwmark+"/"+fwmark,
	); err != nil {
		// TPROXY target not available — clean up and bail.
		_ = r.ipt.DeleteChain(ctx, "mangle", redirectUDPChainName)
		return fmt.Errorf("tproxy target not supported: %w", err)
	}

	if iface != "" {
		if err := r.ipt.AppendRule(ctx, "mangle", "PREROUTING", "-i", iface, "-j", redirectUDPChainName); err != nil {
			_ = r.ipt.DeleteChain(ctx, "mangle", redirectUDPChainName)
			return fmt.Errorf("udp prerouting jump: %w", err)
		}
	} else {
		if err := r.ipt.AppendRule(ctx, "mangle", "PREROUTING", "-j", redirectUDPChainName); err != nil {
			_ = r.ipt.DeleteChain(ctx, "mangle", redirectUDPChainName)
			return fmt.Errorf("udp prerouting jump: %w", err)
		}
	}

	// Policy routing for TPROXY-marked packets.
	if err := platform.RunSilent(ctx, "ip", "rule", "add", "fwmark", fwmark, "table", routeTable); err != nil {
		r.logger.Warn("ip rule add failed (may already exist)", "error", err)
	}
	if err := platform.RunSilent(ctx, "ip", "route", "replace", "local", "0/0", "dev", "lo", "table", routeTable); err != nil {
		return fmt.Errorf("ip route replace: %w", err)
	}

	return nil
}

// TeardownRules removes TCP/UDP redirect chains, policy routing, and DNS DNAT rules.
func (r *Redirect) TeardownRules(ctx context.Context) error {
	r.logger.Info("tearing down redirect iptables rules")

	// TCP: nat table.
	_ = r.ipt.RemoveJumpRules(ctx, "nat", "PREROUTING", redirectChainName)
	_ = r.ipt.DeleteChain(ctx, "nat", redirectChainName)

	// UDP: mangle table.
	_ = r.ipt.RemoveJumpRules(ctx, "mangle", "PREROUTING", redirectUDPChainName)
	_ = r.ipt.DeleteChain(ctx, "mangle", redirectUDPChainName)

	// Policy routing for TPROXY.
	_ = platform.RunSilent(ctx, "ip", "rule", "del", "fwmark", fwmark, "table", routeTable)
	_ = platform.RunSilent(ctx, "ip", "route", "del", "local", "0/0", "table", routeTable)

	// Remove DNS DNAT rules added by the dns-local hook.
	iface := r.cfg.Network.EntwareInterface
	if iface == "" {
		iface = "br0"
	}
	_ = r.ipt.DeleteRule(ctx, "nat", "PREROUTING",
		"-i", iface, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to", "127.0.0.1")
	_ = r.ipt.DeleteRule(ctx, "nat", "PREROUTING",
		"-i", iface, "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to", "127.0.0.1")

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
