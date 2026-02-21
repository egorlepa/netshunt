package proxy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/netfilter"
)

const xrayChainName = "XRAY"

// Xray implements TrafficMode using NAT REDIRECT to a local xray dokodemo-door port.
//
// Traffic flow:
//  1. DNS query matches ipset directive in dnsmasq → IP added to "bypass" ipset
//  2. iptables PREROUTING (nat) checks if destination is in ipset "bypass"
//  3. If matched → REDIRECT TCP to local xray dokodemo-door port (default 1182)
//  4. xray forwards traffic through VLESS+Reality tunnel
//
// Note: UDP redirect via NAT is unreliable for arbitrary UDP traffic.
// DNS is handled separately by dnsmasq on port 53; other UDP traffic uses TCP fallback.
type Xray struct {
	cfg    *config.Config
	ipt    *netfilter.IPTables
	logger *slog.Logger
}

// NewXray creates an Xray traffic mode handler.
func NewXray(cfg *config.Config, logger *slog.Logger) *Xray {
	return &Xray{
		cfg:    cfg,
		ipt:    netfilter.NewIPTables(),
		logger: logger,
	}
}

func (x *Xray) Name() string { return "xray" }

// SetupRules creates the XRAY chain in nat table and redirects matching TCP traffic
// to the local xray dokodemo-door port.
//
//	iptables -t nat -N XRAY
//	iptables -t nat -A XRAY -d <excluded_nets> -j RETURN
//	iptables -t nat -A XRAY -p tcp -m set --match-set bypass dst -j REDIRECT --to-port 1182
//	iptables -t nat -A PREROUTING -i <iface> -j XRAY
func (x *Xray) SetupRules(ctx context.Context) error {
	table := "nat"
	ipsetName := x.cfg.IPSet.TableName
	port := fmt.Sprintf("%d", x.cfg.Xray.LocalPort)
	iface := x.cfg.Network.EntwareInterface

	x.logger.Info("setting up xray iptables rules",
		"ipset", ipsetName, "port", port, "interface", iface)

	if err := x.ipt.CreateChain(ctx, table, xrayChainName); err != nil {
		return fmt.Errorf("create chain: %w", err)
	}

	for _, net := range x.cfg.ExcludedNetworks {
		if err := x.ipt.AppendRule(ctx, table, xrayChainName, "-d", net, "-j", "RETURN"); err != nil {
			return fmt.Errorf("exclude network %s: %w", net, err)
		}
	}

	if err := x.ipt.AppendRule(ctx, table,
		xrayChainName, "-p", "tcp",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "REDIRECT", "--to-port", port,
	); err != nil {
		return fmt.Errorf("tcp redirect rule: %w", err)
	}

	if iface != "" {
		if err := x.ipt.AppendRule(ctx, table,
			"PREROUTING", "-i", iface, "-j", xrayChainName,
		); err != nil {
			return fmt.Errorf("prerouting jump: %w", err)
		}
	} else {
		if err := x.ipt.AppendRule(ctx, table,
			"PREROUTING", "-j", xrayChainName,
		); err != nil {
			return fmt.Errorf("prerouting jump: %w", err)
		}
	}

	return nil
}

// TeardownRules removes all XRAY iptables rules and DNS DNAT rules.
func (x *Xray) TeardownRules(ctx context.Context) error {
	table := "nat"

	x.logger.Info("tearing down xray iptables rules")

	_ = x.ipt.RemoveJumpRules(ctx, table, "PREROUTING", xrayChainName)
	_ = x.ipt.DeleteChain(ctx, table, xrayChainName)

	iface := x.cfg.Network.EntwareInterface
	if iface == "" {
		iface = "br0"
	}
	_ = x.ipt.DeleteRule(ctx, table, "PREROUTING",
		"-i", iface, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to", "127.0.0.1")
	_ = x.ipt.DeleteRule(ctx, table, "PREROUTING",
		"-i", iface, "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to", "127.0.0.1")

	return nil
}

// IsActive checks if xray is listening on the configured local port.
func (x *Xray) IsActive(ctx context.Context) (bool, error) {
	port := fmt.Sprintf(":%d", x.cfg.Xray.LocalPort)
	out, err := netfilter.CheckListeningPort(ctx, port)
	if err != nil {
		return false, nil
	}
	return out, nil
}
