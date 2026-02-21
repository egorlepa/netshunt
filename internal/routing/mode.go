package routing

import (
	"context"
	"log/slog"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
)

// Mode abstracts the mechanism for redirecting traffic matching the ipset.
//
// Two implementations:
//   - Redirect: NAT REDIRECT to a local transparent proxy port (ss-redir, xray, sing-box, …)
//   - Iface: MARK + policy routing via a VPN interface (WireGuard, OpenVPN, …)
type Mode interface {
	// Name returns the mode identifier ("redirect" or "interface").
	Name() string

	// SetupRules creates iptables/ip rules necessary for traffic redirection.
	SetupRules(ctx context.Context) error

	// TeardownRules removes all iptables/ip rules created by SetupRules.
	TeardownRules(ctx context.Context) error

	// IsActive returns true if the proxy/interface appears to be available.
	IsActive(ctx context.Context) (bool, error)
}

// New returns a Mode for the configured routing mode.
func New(cfg *config.Config, logger *slog.Logger) Mode {
	if cfg.Routing.Mode == "interface" {
		return NewIface(cfg, logger)
	}
	return NewRedirect(cfg, logger)
}
