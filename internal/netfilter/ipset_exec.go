package netfilter

import (
	"context"
	"fmt"
	"strings"

	"github.com/egorlepa/netshunt/internal/platform"
)

// execIPSet drives the set through the ipset binary, one process per call.
type execIPSet struct {
	name string
	run  platform.Runner
}

// Ensure creates the set if it doesn't exist. The existence check lists only
// the header (-t), not the members.
func (s execIPSet) Ensure(ctx context.Context) error {
	if _, err := s.run.Run(ctx, "ipset", "list", "-t", s.name); err == nil {
		return nil // already exists
	}
	return s.run.RunSilent(ctx, "ipset", "create", s.name, "hash:net", "hashsize", HashSize, "maxelem", MaxElem)
}

func (s execIPSet) Flush(ctx context.Context) error {
	return s.run.RunSilent(ctx, "ipset", "flush", s.name)
}

func (s execIPSet) Add(ctx context.Context, member string) error {
	return s.run.RunSilent(ctx, "ipset", "add", s.name, member, "-exist")
}

func (s execIPSet) Del(ctx context.Context, member string) error {
	return s.run.RunSilent(ctx, "ipset", "del", s.name, member, "-exist")
}

// AddBatch adds every member in one `ipset restore` process. With -exist
// (-!) members already present are not errors. restore is not transactional:
// on an error the lines before the failing one are applied and the rest are
// not.
func (s execIPSet) AddBatch(ctx context.Context, members []string) error {
	return s.restore(ctx, "add", members)
}

func (s execIPSet) DelBatch(ctx context.Context, members []string) error {
	return s.restore(ctx, "del", members)
}

func (s execIPSet) restore(ctx context.Context, op string, members []string) error {
	if len(members) == 0 {
		return nil
	}
	var b strings.Builder
	for _, m := range members {
		b.WriteString(op)
		b.WriteByte(' ')
		b.WriteString(s.name)
		b.WriteByte(' ')
		b.WriteString(m)
		b.WriteByte('\n')
	}
	_, err := s.run.RunInput(ctx, b.String(), "ipset", "restore", "-!")
	return err
}

func (s execIPSet) List(ctx context.Context) ([]string, error) {
	out, err := s.run.Run(ctx, "ipset", "list", s.name, "-output", "plain")
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

func (s execIPSet) Destroy(ctx context.Context) error {
	return s.run.RunSilent(ctx, "ipset", "destroy", s.name)
}
