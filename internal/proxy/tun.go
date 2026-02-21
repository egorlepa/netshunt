package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/netfilter"
	"github.com/guras256/keenetic-split-tunnel/internal/platform"
)

const (
	tunChainName  = "KSTMARK"
	tunFwmark     = "0x1"
	tunRouteTable = "100"
)

// Tun implements TrafficMode using MARK + policy routing via a VPN interface.
//
// This works with any VPN that creates a tunnel interface:
// WireGuard (wg0), OpenVPN (tun0), etc.
//
// Traffic flow:
//  1. DNS query resolved → IP added to ipset by dnsmasq
//  2. iptables PREROUTING (mangle) marks packets destined for ipset addresses
//  3. ip rule routes marked packets via routing table 100
//  4. Default route in table 100 sends traffic via cfg.Proxy.Interface
type Tun struct {
	cfg    *config.Config
	ipt    *netfilter.IPTables
	logger *slog.Logger
}

// NewTun creates a Tun traffic mode handler.
func NewTun(cfg *config.Config, logger *slog.Logger) *Tun {
	return &Tun{
		cfg:    cfg,
		ipt:    netfilter.NewIPTables(),
		logger: logger,
	}
}

func (t *Tun) Name() string { return "tun" }

// SetupRules creates the KSTMARK chain in mangle table and adds ip rule/route
// to forward marked traffic via the VPN interface.
//
//	iptables -t mangle -N KSTMARK
//	iptables -t mangle -A KSTMARK -d <excluded_net> -j RETURN
//	iptables -t mangle -A KSTMARK -m set --match-set <table> dst -j MARK --set-mark 0x1
//	iptables -t mangle -A PREROUTING [-i <iface>] -j KSTMARK
//	ip rule add fwmark 0x1 table 100
//	ip route replace default dev <interface> table 100
func (t *Tun) SetupRules(ctx context.Context) error {
	table := "mangle"
	ipsetName := t.cfg.IPSet.TableName
	iface := t.cfg.Network.EntwareInterface
	vpnIface := t.cfg.Proxy.Interface

	t.logger.Info("setting up tun iptables rules",
		"ipset", ipsetName, "vpn_interface", vpnIface, "entware_interface", iface)

	if err := t.ipt.CreateChain(ctx, table, tunChainName); err != nil {
		return fmt.Errorf("create chain: %w", err)
	}

	for _, net := range t.cfg.ExcludedNetworks {
		if err := t.ipt.AppendRule(ctx, table, tunChainName, "-d", net, "-j", "RETURN"); err != nil {
			return fmt.Errorf("exclude network %s: %w", net, err)
		}
	}

	if err := t.ipt.AppendRule(ctx, table,
		tunChainName,
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "MARK", "--set-mark", tunFwmark,
	); err != nil {
		return fmt.Errorf("mark rule: %w", err)
	}

	if iface != "" {
		if err := t.ipt.AppendRule(ctx, table, "PREROUTING", "-i", iface, "-j", tunChainName); err != nil {
			return fmt.Errorf("prerouting jump: %w", err)
		}
	} else {
		if err := t.ipt.AppendRule(ctx, table, "PREROUTING", "-j", tunChainName); err != nil {
			return fmt.Errorf("prerouting jump: %w", err)
		}
	}

	// Add ip rule to route marked packets via table 100.
	if err := platform.RunSilent(ctx, "ip", "rule", "add", "fwmark", tunFwmark, "table", tunRouteTable); err != nil {
		t.logger.Warn("ip rule add failed (may already exist)", "error", err)
	}

	// Add default route via the VPN interface in table 100.
	if vpnIface != "" {
		if err := platform.RunSilent(ctx, "ip", "route", "replace", "default", "dev", vpnIface, "table", tunRouteTable); err != nil {
			return fmt.Errorf("ip route replace: %w", err)
		}
	}

	return nil
}

// TeardownRules removes the KSTMARK chain, ip rule, and ip route.
func (t *Tun) TeardownRules(ctx context.Context) error {
	table := "mangle"

	t.logger.Info("tearing down tun iptables rules")

	_ = t.ipt.RemoveJumpRules(ctx, table, "PREROUTING", tunChainName)
	_ = t.ipt.DeleteChain(ctx, table, tunChainName)

	_ = platform.RunSilent(ctx, "ip", "rule", "del", "fwmark", tunFwmark, "table", tunRouteTable)
	_ = platform.RunSilent(ctx, "ip", "route", "del", "default", "table", tunRouteTable)

	return nil
}

// IsActive checks if the configured VPN interface exists and is UP.
func (t *Tun) IsActive(ctx context.Context) (bool, error) {
	iface := t.cfg.Proxy.Interface
	if iface == "" {
		return false, nil
	}
	data, err := os.ReadFile("/sys/class/net/" + iface + "/operstate")
	if err != nil {
		return false, nil
	}
	state := strings.TrimSpace(string(data))
	return state == "up" || state == "unknown", nil
}
