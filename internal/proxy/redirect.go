package proxy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/netfilter"
)

const redirectChainName = "KSTREDIR"

// Redirect implements TrafficMode using NAT REDIRECT to a local transparent proxy port.
//
// This works with any transparent proxy that listens on a local TCP port:
// ss-redir, xray (dokodemo-door), sing-box, redsocks, etc.
//
// Traffic flow:
//  1. DNS query resolved → IP added to ipset by dnsmasq
//  2. iptables PREROUTING (nat) matches destination in ipset
//  3. TCP traffic redirected to cfg.Proxy.LocalPort
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

// SetupRules creates the KSTREDIR chain in nat table and redirects matching
// TCP traffic to the configured local port.
//
//	iptables -t nat -N KSTREDIR
//	iptables -t nat -A KSTREDIR -d <excluded_net> -j RETURN
//	iptables -t nat -A KSTREDIR -p tcp -m set --match-set <table> dst -j REDIRECT --to-port <port>
//	iptables -t nat -A PREROUTING [-i <iface>] -j KSTREDIR
func (r *Redirect) SetupRules(ctx context.Context) error {
	table := "nat"
	ipsetName := r.cfg.IPSet.TableName
	port := fmt.Sprintf("%d", r.cfg.Proxy.LocalPort)
	iface := r.cfg.Network.EntwareInterface

	r.logger.Info("setting up redirect iptables rules",
		"ipset", ipsetName, "port", port, "interface", iface)

	if err := r.ipt.CreateChain(ctx, table, redirectChainName); err != nil {
		return fmt.Errorf("create chain: %w", err)
	}

	for _, net := range r.cfg.ExcludedNetworks {
		if err := r.ipt.AppendRule(ctx, table, redirectChainName, "-d", net, "-j", "RETURN"); err != nil {
			return fmt.Errorf("exclude network %s: %w", net, err)
		}
	}

	if err := r.ipt.AppendRule(ctx, table,
		redirectChainName, "-p", "tcp",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "REDIRECT", "--to-port", port,
	); err != nil {
		return fmt.Errorf("tcp redirect rule: %w", err)
	}

	if iface != "" {
		if err := r.ipt.AppendRule(ctx, table, "PREROUTING", "-i", iface, "-j", redirectChainName); err != nil {
			return fmt.Errorf("prerouting jump: %w", err)
		}
	} else {
		if err := r.ipt.AppendRule(ctx, table, "PREROUTING", "-j", redirectChainName); err != nil {
			return fmt.Errorf("prerouting jump: %w", err)
		}
	}

	return nil
}

// TeardownRules removes the KSTREDIR chain and DNS DNAT rules.
func (r *Redirect) TeardownRules(ctx context.Context) error {
	table := "nat"

	r.logger.Info("tearing down redirect iptables rules")

	_ = r.ipt.RemoveJumpRules(ctx, table, "PREROUTING", redirectChainName)
	_ = r.ipt.DeleteChain(ctx, table, redirectChainName)

	// Remove DNS DNAT rules added by the dns-local hook.
	iface := r.cfg.Network.EntwareInterface
	if iface == "" {
		iface = "br0"
	}
	_ = r.ipt.DeleteRule(ctx, table, "PREROUTING",
		"-i", iface, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to", "127.0.0.1")
	_ = r.ipt.DeleteRule(ctx, table, "PREROUTING",
		"-i", iface, "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to", "127.0.0.1")

	return nil
}

// IsActive checks if something is listening on the configured local port.
func (r *Redirect) IsActive(ctx context.Context) (bool, error) {
	port := fmt.Sprintf(":%d", r.cfg.Proxy.LocalPort)
	ok, err := netfilter.CheckListeningPort(ctx, port)
	if err != nil {
		return false, nil
	}
	return ok, nil
}
