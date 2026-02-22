package netfilter

import (
	"context"
	"fmt"
	"strings"

	"github.com/egorlepa/netshunt/internal/platform"
)

// IPTables manages iptables rules for traffic redirection.
type IPTables struct{}

// NewIPTables creates an IPTables manager.
func NewIPTables() *IPTables {
	return &IPTables{}
}

// ChainExists checks if a chain exists in the given table.
func (ipt *IPTables) ChainExists(ctx context.Context, table, chain string) (bool, error) {
	err := platform.RunSilent(ctx, "iptables", "-t", table, "-L", chain, "-n")
	return err == nil, nil
}

// CreateChain creates a new chain in the given table if it doesn't exist.
func (ipt *IPTables) CreateChain(ctx context.Context, table, chain string) error {
	exists, _ := ipt.ChainExists(ctx, table, chain)
	if exists {
		return nil
	}
	return platform.RunSilent(ctx, "iptables", "-t", table, "-N", chain)
}

// DeleteChain flushes and removes a chain from the given table.
func (ipt *IPTables) DeleteChain(ctx context.Context, table, chain string) error {
	exists, _ := ipt.ChainExists(ctx, table, chain)
	if !exists {
		return nil
	}
	// Flush the chain first.
	_ = platform.RunSilent(ctx, "iptables", "-t", table, "-F", chain)
	return platform.RunSilent(ctx, "iptables", "-t", table, "-X", chain)
}

// RuleExists checks if a specific rule exists.
func (ipt *IPTables) RuleExists(ctx context.Context, table string, ruleSpec ...string) bool {
	args := append([]string{"-t", table, "-C"}, ruleSpec...)
	return platform.RunSilent(ctx, "iptables", args...) == nil
}

// AppendRule adds a rule if it doesn't already exist.
func (ipt *IPTables) AppendRule(ctx context.Context, table string, ruleSpec ...string) error {
	if ipt.RuleExists(ctx, table, ruleSpec...) {
		return nil
	}
	args := append([]string{"-t", table, "-A"}, ruleSpec...)
	return platform.RunSilent(ctx, "iptables", args...)
}

// InsertRule inserts a rule at position 1 if it doesn't already exist.
func (ipt *IPTables) InsertRule(ctx context.Context, table string, ruleSpec ...string) error {
	if ipt.RuleExists(ctx, table, ruleSpec...) {
		return nil
	}
	args := append([]string{"-t", table, "-I"}, ruleSpec...)
	return platform.RunSilent(ctx, "iptables", args...)
}

// DeleteRule removes a rule if it exists.
func (ipt *IPTables) DeleteRule(ctx context.Context, table string, ruleSpec ...string) error {
	if !ipt.RuleExists(ctx, table, ruleSpec...) {
		return nil
	}
	args := append([]string{"-t", table, "-D"}, ruleSpec...)
	return platform.RunSilent(ctx, "iptables", args...)
}

// RemoveJumpRules removes all jump rules to the given chain from a parent chain.
func (ipt *IPTables) RemoveJumpRules(ctx context.Context, table, parentChain, targetChain string) error {
	out, err := platform.Run(ctx, "iptables", "-t", table, "-L", parentChain, "--line-numbers", "-n")
	if err != nil {
		return nil // Parent chain doesn't exist, nothing to do.
	}

	// Collect line numbers in reverse order (delete from bottom up).
	var lineNums []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == targetChain {
			lineNums = append([]string{fields[0]}, lineNums...)
		}
	}

	for _, num := range lineNums {
		if err := platform.RunSilent(ctx, "iptables", "-t", table, "-D", parentChain, num); err != nil {
			return fmt.Errorf("delete rule %s from %s: %w", num, parentChain, err)
		}
	}
	return nil
}
