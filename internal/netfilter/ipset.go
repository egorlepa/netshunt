package netfilter

import (
	"context"
	"fmt"
	"strings"

	"github.com/egorlepa/netshunt/internal/platform"
)

// IPSet manages an ipset hash:net table.
type IPSet struct {
	Name   string
	family string // "inet" or "inet6"; empty defaults to inet
}

// NewIPSet creates an IPSet manager for the given table name (IPv4).
func NewIPSet(name string) *IPSet {
	return &IPSet{Name: name}
}

// NewIPSet6 creates an IPSet manager for IPv6 (hash:net family inet6).
func NewIPSet6(name string) *IPSet {
	return &IPSet{Name: name, family: "inet6"}
}

// EnsureTable creates the ipset table if it doesn't exist.
func (s *IPSet) EnsureTable(ctx context.Context) error {
	_, err := platform.Run(ctx, "ipset", "list", s.Name)
	if err == nil {
		return nil // already exists
	}
	args := []string{"create", s.Name, "hash:net"}
	if s.family != "" {
		args = append(args, "family", s.family)
	}
	return platform.RunSilent(ctx, "ipset", args...)
}

// Flush removes all entries from the table.
func (s *IPSet) Flush(ctx context.Context) error {
	return platform.RunSilent(ctx, "ipset", "flush", s.Name)
}

// Add adds an IP or CIDR to the table.
func (s *IPSet) Add(ctx context.Context, entry string) error {
	return platform.RunSilent(ctx, "ipset", "add", s.Name, entry, "-exist")
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
