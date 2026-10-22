package netfilter

import (
	"context"
	"fmt"
	"strings"

	"github.com/egorlepa/netshunt/internal/platform"
)

// IPSet manages an ipset hash:net table.
type IPSet struct {
	Name string
	// Runner executes ipset; nil means platform.DefaultRunner.
	Runner platform.Runner
}

// NewIPSet creates an IPSet manager for the given table name.
func NewIPSet(name string) *IPSet {
	return &IPSet{Name: name}
}

// MaxElem is the capacity a new set is created with. The kernel default
// (65536) is within reach of a geosite-heavy setup; an existing set keeps
// its size until it is recreated or swapped.
const MaxElem = "262144"

// HashSize is the initial bucket count of a new set. The Keenetic 4.9 kernel
// has a hash:net bug: once a set created with the default hashsize (1024)
// holds about 1000 members and has to grow, deleting a member can silently
// drop unrelated members or fail with "not added" (reproduced on the
// router with 2000 /32s: 1154 left after deleting all; clean at hashsize
// 8192). A large initial hashsize keeps the set from ever resizing in
// practice. Cost: about 400 KB of kernel memory for an empty set.
const HashSize = "16384"

// EnsureTable creates the ipset table if it doesn't exist. The existence
// check lists only the header (-t), not the members.
func (s *IPSet) EnsureTable(ctx context.Context) error {
	_, err := platform.OrDefault(s.Runner).Run(ctx, "ipset", "list", "-t", s.Name)
	if err == nil {
		return nil // already exists
	}
	return platform.OrDefault(s.Runner).RunSilent(ctx, "ipset", "create", s.Name, "hash:net", "hashsize", HashSize, "maxelem", MaxElem)
}

// Flush removes all entries from the table.
func (s *IPSet) Flush(ctx context.Context) error {
	return platform.OrDefault(s.Runner).RunSilent(ctx, "ipset", "flush", s.Name)
}

// Add adds an IP or CIDR to the table.
func (s *IPSet) Add(ctx context.Context, entry string) error {
	return platform.OrDefault(s.Runner).RunSilent(ctx, "ipset", "add", s.Name, entry, "-exist")
}

// Del removes an IP or CIDR from the table.
func (s *IPSet) Del(ctx context.Context, entry string) error {
	return platform.OrDefault(s.Runner).RunSilent(ctx, "ipset", "del", s.Name, entry, "-exist")
}

// AddBatch adds every member in one `ipset restore` process. With -exist
// (-!) members already present are not errors. restore is not transactional:
// on an error the lines before the failing one are applied and the rest are
// not, so callers fall back to per-member calls to learn the exact state.
func (s *IPSet) AddBatch(ctx context.Context, members []string) error {
	return s.restore(ctx, "add", members)
}

// DelBatch removes every member in one `ipset restore` process; see AddBatch.
func (s *IPSet) DelBatch(ctx context.Context, members []string) error {
	return s.restore(ctx, "del", members)
}

func (s *IPSet) restore(ctx context.Context, op string, members []string) error {
	if len(members) == 0 {
		return nil
	}
	var b strings.Builder
	for _, m := range members {
		b.WriteString(op)
		b.WriteByte(' ')
		b.WriteString(s.Name)
		b.WriteByte(' ')
		b.WriteString(m)
		b.WriteByte('\n')
	}
	_, err := platform.OrDefault(s.Runner).RunInput(ctx, b.String(), "ipset", "restore", "-!")
	return err
}

// List returns all entries in the table.
func (s *IPSet) List(ctx context.Context) ([]string, error) {
	out, err := platform.OrDefault(s.Runner).Run(ctx, "ipset", "list", s.Name, "-output", "plain")
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
	return platform.OrDefault(s.Runner).RunSilent(ctx, "ipset", "destroy", s.Name)
}
