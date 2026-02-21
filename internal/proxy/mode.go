package proxy

import (
	"context"
	"log/slog"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
)

// TrafficMode abstracts the mechanism for redirecting traffic matching the ipset.
//
// Two implementations:
//   - Redirect: NAT REDIRECT to a local transparent proxy port (ss-redir, xray, sing-box, …)
//   - Tun: MARK + policy routing via a VPN interface (WireGuard, OpenVPN, …)
type TrafficMode interface {
	// Name returns the mode identifier ("redirect" or "tun").
	Name() string

	// SetupRules creates iptables/ip rules necessary for traffic redirection.
	SetupRules(ctx context.Context) error

	// TeardownRules removes all iptables/ip rules created by SetupRules.
	TeardownRules(ctx context.Context) error

	// IsActive returns true if the proxy/interface appears to be available.
	IsActive(ctx context.Context) (bool, error)
}

// NewMode returns a TrafficMode for the configured proxy type.
func NewMode(cfg *config.Config, logger *slog.Logger) TrafficMode {
	if cfg.Proxy.Type == "tun" {
		return NewTun(cfg, logger)
	}
	return NewRedirect(cfg, logger)
}
