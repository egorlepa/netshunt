package proxy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/netfilter"
)

const ssChainName = "SHADOWSOCKS"

// Shadowsocks implements TrafficMode using NAT REDIRECT to a local ss-redir port.
//
// Traffic flow:
//  1. DNS query matches ipset directive in dnsmasq → IP added to "unblock" ipset
//  2. iptables PREROUTING (nat) checks if destination is in ipset "unblock"
//  3. If matched → REDIRECT TCP/UDP to local ss-redir port (default 1181)
//  4. ss-redir forwards traffic through the Shadowsocks tunnel
type Shadowsocks struct {
	cfg    *config.Config
	ipt    *netfilter.IPTables
	logger *slog.Logger
}

// NewShadowsocks creates a Shadowsocks traffic mode handler.
func NewShadowsocks(cfg *config.Config, logger *slog.Logger) *Shadowsocks {
	return &Shadowsocks{
		cfg:    cfg,
		ipt:    netfilter.NewIPTables(),
		logger: logger,
	}
}

func (s *Shadowsocks) Name() string { return "shadowsocks" }

// SetupRules creates the SHADOWSOCKS chain in nat table and redirects matching
// traffic to the local ss-redir port.
//
// Equivalent to original KVAS /opt/etc/ndm/netfilter.d/100-proxy-redirect:
//
//	iptables -t nat -N SHADOWSOCKS
//	iptables -t nat -A SHADOWSOCKS -d <excluded_nets> -j RETURN
//	iptables -t nat -A SHADOWSOCKS -p tcp -m set --match-set unblock dst -j REDIRECT --to-port 1181
//	iptables -t nat -A SHADOWSOCKS -p udp -m set --match-set unblock dst -j REDIRECT --to-port 1181
//	iptables -t nat -A PREROUTING -i <iface> -j SHADOWSOCKS
func (s *Shadowsocks) SetupRules(ctx context.Context) error {
	table := "nat"
	ipsetName := s.cfg.IPSet.TableName
	port := fmt.Sprintf("%d", s.cfg.Shadowsocks.LocalPort)
	iface := s.cfg.Network.EntwareInterface

	s.logger.Info("setting up shadowsocks iptables rules",
		"ipset", ipsetName, "port", port, "interface", iface)

	// Create the chain.
	if err := s.ipt.CreateChain(ctx, table, ssChainName); err != nil {
		return fmt.Errorf("create chain: %w", err)
	}

	// Exclude local/private networks from redirection.
	for _, net := range s.cfg.ExcludedNetworks {
		if err := s.ipt.AppendRule(ctx, table, ssChainName, "-d", net, "-j", "RETURN"); err != nil {
			return fmt.Errorf("exclude network %s: %w", net, err)
		}
	}

	// Redirect TCP traffic matching ipset to ss-redir.
	if err := s.ipt.AppendRule(ctx, table,
		ssChainName, "-p", "tcp",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "REDIRECT", "--to-port", port,
	); err != nil {
		return fmt.Errorf("tcp redirect rule: %w", err)
	}

	// Redirect UDP traffic matching ipset to ss-redir.
	if err := s.ipt.AppendRule(ctx, table,
		ssChainName, "-p", "udp",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "REDIRECT", "--to-port", port,
	); err != nil {
		return fmt.Errorf("udp redirect rule: %w", err)
	}

	// Jump from PREROUTING to our chain.
	if iface != "" {
		if err := s.ipt.AppendRule(ctx, table,
			"PREROUTING", "-i", iface, "-j", ssChainName,
		); err != nil {
			return fmt.Errorf("prerouting jump: %w", err)
		}
	} else {
		if err := s.ipt.AppendRule(ctx, table,
			"PREROUTING", "-j", ssChainName,
		); err != nil {
			return fmt.Errorf("prerouting jump: %w", err)
		}
	}

	return nil
}

// TeardownRules removes all Shadowsocks iptables rules.
func (s *Shadowsocks) TeardownRules(ctx context.Context) error {
	table := "nat"

	s.logger.Info("tearing down shadowsocks iptables rules")

	// Remove jump rules from PREROUTING.
	_ = s.ipt.RemoveJumpRules(ctx, table, "PREROUTING", ssChainName)

	// Flush and delete the chain.
	_ = s.ipt.DeleteChain(ctx, table, ssChainName)

	return nil
}

// IsActive checks if ss-redir is listening on the configured port.
func (s *Shadowsocks) IsActive(ctx context.Context) (bool, error) {
	port := fmt.Sprintf(":%d", s.cfg.Shadowsocks.LocalPort)
	// Check if something is listening on the ss-redir port.
	out, err := netfilter.CheckListeningPort(ctx, port)
	if err != nil {
		return false, nil
	}
	return out, nil
}
