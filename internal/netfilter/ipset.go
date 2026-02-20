package netfilter

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/guras256/keenetic-split-tunnel/internal/platform"
)

// entryTimeout is the TTL for ipset entries in seconds.
// dnsmasq re-adds IPs on every DNS query (refreshing TTL).
// IP/CIDR entries are re-added by the daemon periodically.
// Entries for removed domains expire naturally after this interval.
const entryTimeout = 86400 // 24 hours

// IPSet manages an ipset hash:net table.
type IPSet struct {
	Name string
}

// NewIPSet creates an IPSet manager for the given table name.
func NewIPSet(name string) *IPSet {
	return &IPSet{Name: name}
}

// EnsureTable creates the ipset table with timeout support if it doesn't exist.
// If the table exists without timeout support, it is destroyed and recreated.
func (s *IPSet) EnsureTable(ctx context.Context) error {
	out, err := platform.Run(ctx, "ipset", "list", s.Name)
	if err == nil {
		// Table exists — check if it has timeout support.
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "Header:") && strings.Contains(line, "timeout") {
				return nil // already good
			}
		}
		// Exists without timeout — destroy and recreate.
		if err := platform.RunSilent(ctx, "ipset", "destroy", s.Name); err != nil {
			return fmt.Errorf("destroy incompatible ipset table: %w", err)
		}
	}
	return platform.RunSilent(ctx, "ipset", "create", s.Name, "hash:net",
		"timeout", strconv.Itoa(entryTimeout))
}

// Flush removes all entries from the table.
func (s *IPSet) Flush(ctx context.Context) error {
	return platform.RunSilent(ctx, "ipset", "flush", s.Name)
}

// Add adds an IP or CIDR to the table as a permanent entry (timeout 0).
// The set's default timeout applies only to entries added by dnsmasq.
func (s *IPSet) Add(ctx context.Context, entry string) error {
	return platform.RunSilent(ctx, "ipset", "add", s.Name, entry,
		"timeout", "0", "-exist")
}

// Del removes an IP or CIDR from the table.
func (s *IPSet) Del(ctx context.Context, entry string) error {
	return platform.RunSilent(ctx, "ipset", "del", s.Name, entry, "-exist")
}

// List returns all entries in the table.
func (s *IPSet) List(ctx context.Context) ([]string, error) {
	out, err := platform.Run(ctx, "ipset", "list", s.Name, "-output", "plain")
	if err != nil {
		return nil, fmt.Errorf("ipset list: %w", err)
	}

	var entries []string
	inMembers := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "Members:" {
			inMembers = true
			continue
		}
		if inMembers && line != "" {
			entries = append(entries, line)
		}
	}
	return entries, nil
}

// Count returns the number of entries in the table.
func (s *IPSet) Count(ctx context.Context) (int, error) {
	entries, err := s.List(ctx)
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

// Destroy removes the table entirely.
func (s *IPSet) Destroy(ctx context.Context) error {
	return platform.RunSilent(ctx, "ipset", "destroy", s.Name)
}
