package netfilter

import (
	"context"
	"fmt"
	"strings"

	"github.com/egorlepa/netshunt/internal/platform"
)

// IPTables manages iptables rules for traffic redirection.
// All commands use -w to wait for the xtables lock.
type IPTables struct {
	cmd string // "iptables" or "ip6tables"
}

// NewIPTables creates an IPTables manager for IPv4.
func NewIPTables() *IPTables {
	return &IPTables{cmd: "iptables"}
}

// NewIP6Tables creates an IPTables manager for IPv6.
func NewIP6Tables() *IPTables {
	return &IPTables{cmd: "ip6tables"}
}

func (ipt *IPTables) iptables(args ...string) (string, []string) {
	return ipt.cmd, append([]string{"-w"}, args...)
}

// ChainExists checks if a chain exists in the given table.
func (ipt *IPTables) ChainExists(ctx context.Context, table, chain string) (bool, error) {
	cmd, args := ipt.iptables("-t", table, "-L", chain, "-n")
	err := platform.RunSilent(ctx, cmd, args...)
	return err == nil, nil
}

// CreateChain creates a new chain in the given table if it doesn't exist.
func (ipt *IPTables) CreateChain(ctx context.Context, table, chain string) error {
	exists, _ := ipt.ChainExists(ctx, table, chain)
	if exists {
		return nil
	}
	cmd, args := ipt.iptables("-t", table, "-N", chain)
	return platform.RunSilent(ctx, cmd, args...)
}

// DeleteChain flushes and removes a chain from the given table.
func (ipt *IPTables) DeleteChain(ctx context.Context, table, chain string) error {
	exists, _ := ipt.ChainExists(ctx, table, chain)
	if !exists {
		return nil
	}
	cmd, args := ipt.iptables("-t", table, "-F", chain)
	_ = platform.RunSilent(ctx, cmd, args...)
	cmd, args = ipt.iptables("-t", table, "-X", chain)
	return platform.RunSilent(ctx, cmd, args...)
}

// RuleExists checks if a specific rule exists.
func (ipt *IPTables) RuleExists(ctx context.Context, table string, ruleSpec ...string) bool {
	cmd, args := ipt.iptables(append([]string{"-t", table, "-C"}, ruleSpec...)...)
	return platform.RunSilent(ctx, cmd, args...) == nil
}

// AppendRule adds a rule if it doesn't already exist.
func (ipt *IPTables) AppendRule(ctx context.Context, table string, ruleSpec ...string) error {
	if ipt.RuleExists(ctx, table, ruleSpec...) {
		return nil
	}
	cmd, args := ipt.iptables(append([]string{"-t", table, "-A"}, ruleSpec...)...)
	return platform.RunSilent(ctx, cmd, args...)
}

// InsertRule inserts a rule at position 1 if it doesn't already exist.
func (ipt *IPTables) InsertRule(ctx context.Context, table string, ruleSpec ...string) error {
	if ipt.RuleExists(ctx, table, ruleSpec...) {
		return nil
	}
	cmd, args := ipt.iptables(append([]string{"-t", table, "-I"}, ruleSpec...)...)
	return platform.RunSilent(ctx, cmd, args...)
}

// DeleteRule removes a rule if it exists.
func (ipt *IPTables) DeleteRule(ctx context.Context, table string, ruleSpec ...string) error {
	if !ipt.RuleExists(ctx, table, ruleSpec...) {
		return nil
	}
	cmd, args := ipt.iptables(append([]string{"-t", table, "-D"}, ruleSpec...)...)
	return platform.RunSilent(ctx, cmd, args...)
}

// RemoveJumpRules removes all jump rules to the given chain from a parent chain.
func (ipt *IPTables) RemoveJumpRules(ctx context.Context, table, parentChain, targetChain string) error {
	cmd, args := ipt.iptables("-t", table, "-L", parentChain, "--line-numbers", "-n")
	out, err := platform.Run(ctx, cmd, args...)
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
		cmd, args := ipt.iptables("-t", table, "-D", parentChain, num)
		if err := platform.RunSilent(ctx, cmd, args...); err != nil {
			return fmt.Errorf("delete rule %s from %s: %w", num, parentChain, err)
		}
	}
	return nil
}
