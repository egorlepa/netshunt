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

	// Reconcile converges the iptables/ip rules to the current config
	// without tearing anything down first: missing rules are added, stale
	// ones of ours removed, foreign rules never touched. When nothing
	// differs it runs read-only commands only.
	Reconcile(ctx context.Context) error

	// TeardownRules removes every rule Reconcile manages (uninstall).
	TeardownRules(ctx context.Context) error

	// IsActive returns true if the proxy appears to be available.
	IsActive(ctx context.Context) (bool, error)
}

// New returns a Mode for the configured routing mode.
func New(cfg *config.Live, logger *slog.Logger) Mode {
	return NewRedirect(cfg, logger)
}
