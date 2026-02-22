package routing

import (
	"context"
	"log/slog"

	"github.com/egorlepa/netshunt/internal/config"
)

// Mode abstracts the mechanism for redirecting traffic matching the ipset.
type Mode interface {
	// Name returns the mode identifier.
	Name() string

	// SetupRules creates iptables/ip rules necessary for traffic redirection.
	SetupRules(ctx context.Context) error

	// TeardownRules removes all iptables/ip rules created by SetupRules.
	TeardownRules(ctx context.Context) error

	// IsActive returns true if the proxy appears to be available.
	IsActive(ctx context.Context) (bool, error)
}

// New returns a Mode for the configured routing mode.
func New(cfg *config.Config, logger *slog.Logger) Mode {
	return NewRedirect(cfg, logger)
}
