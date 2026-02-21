package routing

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
	ifaceChainName  = "KSTMARK"
	ifaceFwmark     = "0x1"
	ifaceRouteTable = "100"
)

// Iface implements Mode using MARK + policy routing via a VPN interface.
//
// This works with any VPN that creates a tunnel interface:
// WireGuard (wg0), OpenVPN (tun0), etc.
//
// Traffic flow:
//  1. DNS query resolved → IP added to ipset by dnsmasq
//  2. iptables PREROUTING (mangle) marks packets destined for ipset addresses
//  3. ip rule routes marked packets via routing table 100
//  4. Default route in table 100 sends traffic via cfg.Routing.Interface
type Iface struct {
	cfg    *config.Config
	ipt    *netfilter.IPTables
	logger *slog.Logger
}

// NewIface creates an Iface traffic mode handler.
func NewIface(cfg *config.Config, logger *slog.Logger) *Iface {
	return &Iface{
		cfg:    cfg,
		ipt:    netfilter.NewIPTables(),
		logger: logger,
	}
}

func (t *Iface) Name() string { return "interface" }

// SetupRules creates the KSTMARK chain in mangle table and adds ip rule/route
// to forward marked traffic via the VPN interface.
//
//	iptables -t mangle -N KSTMARK
//	iptables -t mangle -A KSTMARK -d <excluded_net> -j RETURN
//	iptables -t mangle -A KSTMARK -m set --match-set <table> dst -j MARK --set-mark 0x1
//	iptables -t mangle -A PREROUTING [-i <iface>] -j KSTMARK
//	ip rule add fwmark 0x1 table 100
//	ip route replace default dev <interface> table 100
func (t *Iface) SetupRules(ctx context.Context) error {
	table := "mangle"
	ipsetName := t.cfg.IPSet.TableName
	iface := t.cfg.Network.EntwareInterface
	vpnIface := t.cfg.Routing.Interface

	t.logger.Info("setting up interface iptables rules",
		"ipset", ipsetName, "vpn_interface", vpnIface, "entware_interface", iface)

	if err := t.ipt.CreateChain(ctx, table, ifaceChainName); err != nil {
		return fmt.Errorf("create chain: %w", err)
	}

	for _, net := range t.cfg.ExcludedNetworks {
		if err := t.ipt.AppendRule(ctx, table, ifaceChainName, "-d", net, "-j", "RETURN"); err != nil {
			return fmt.Errorf("exclude network %s: %w", net, err)
		}
	}

	if err := t.ipt.AppendRule(ctx, table,
		ifaceChainName,
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "MARK", "--set-mark", ifaceFwmark,
	); err != nil {
		return fmt.Errorf("mark rule: %w", err)
	}

	if iface != "" {
		if err := t.ipt.AppendRule(ctx, table, "PREROUTING", "-i", iface, "-j", ifaceChainName); err != nil {
			return fmt.Errorf("prerouting jump: %w", err)
		}
	} else {
		if err := t.ipt.AppendRule(ctx, table, "PREROUTING", "-j", ifaceChainName); err != nil {
			return fmt.Errorf("prerouting jump: %w", err)
		}
	}

	// Add ip rule to route marked packets via table 100.
	if err := platform.RunSilent(ctx, "ip", "rule", "add", "fwmark", ifaceFwmark, "table", ifaceRouteTable); err != nil {
		t.logger.Warn("ip rule add failed (may already exist)", "error", err)
	}

	// Add default route via the VPN interface in table 100.
	if vpnIface != "" {
		if err := platform.RunSilent(ctx, "ip", "route", "replace", "default", "dev", vpnIface, "table", ifaceRouteTable); err != nil {
			return fmt.Errorf("ip route replace: %w", err)
		}
	}

	return nil
}

// TeardownRules removes the KSTMARK chain, ip rule, and ip route.
func (t *Iface) TeardownRules(ctx context.Context) error {
	table := "mangle"

	t.logger.Info("tearing down interface iptables rules")

	_ = t.ipt.RemoveJumpRules(ctx, table, "PREROUTING", ifaceChainName)
	_ = t.ipt.DeleteChain(ctx, table, ifaceChainName)

	_ = platform.RunSilent(ctx, "ip", "rule", "del", "fwmark", ifaceFwmark, "table", ifaceRouteTable)
	_ = platform.RunSilent(ctx, "ip", "route", "del", "default", "table", ifaceRouteTable)

	return nil
}

// IsActive checks if the configured VPN interface exists and is UP.
func (t *Iface) IsActive(ctx context.Context) (bool, error) {
	iface := t.cfg.Routing.Interface
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
