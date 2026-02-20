package proxy

import "context"

// TrafficMode abstracts the mechanism for redirecting traffic matching the ipset.
// Shadowsocks uses NAT REDIRECT to a local ss-redir port.
// VPN (future) would use MARK + policy routing to a tunnel interface.
type TrafficMode interface {
	// Name returns the mode identifier (e.g., "shadowsocks").
	Name() string

	// SetupRules creates iptables/ip rules necessary for traffic redirection.
	SetupRules(ctx context.Context) error

	// TeardownRules removes all iptables/ip rules created by SetupRules.
	TeardownRules(ctx context.Context) error

	// IsActive returns true if the underlying service is running.
	IsActive(ctx context.Context) (bool, error)
}
