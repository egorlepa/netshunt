package netfilter

import (
	"context"
	"log/slog"

	"github.com/egorlepa/netshunt/internal/platform"
)

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

// Numeric forms of HashSize and MaxElem for the netlink backend.
const (
	hashSizeN uint32 = 16384
	maxElemN  uint32 = 262144
)

// IPSetBackend is one way of driving an IPv4 hash:net set. Members are
// strings in the form `ipset list` prints: a bare address for a host, a
// masked network/bits otherwise.
type IPSetBackend interface {
	// Ensure creates the set (hash:net, HashSize, MaxElem) if it is missing.
	Ensure(ctx context.Context) error
	// Add and Del ignore a member already present / already absent, like
	// `ipset -exist`.
	Add(ctx context.Context, member string) error
	Del(ctx context.Context, member string) error
	// AddBatch and DelBatch apply many members. Not transactional: on an
	// error a prefix of members may be applied.
	AddBatch(ctx context.Context, members []string) error
	DelBatch(ctx context.Context, members []string) error
	List(ctx context.Context) ([]string, error)
	Flush(ctx context.Context) error
	Destroy(ctx context.Context) error
}

// IPSet manages an ipset hash:net table. NewIPSet drives it through netlink
// when the kernel allows it and through the ipset binary otherwise; a zero
// IPSet{Name, Runner} literal always uses exec (tests).
type IPSet struct {
	Name string
	// Runner executes ipset for the exec backend; nil means
	// platform.DefaultRunner.
	Runner platform.Runner

	nl     *fallback[IPSetBackend] // nil: exec only
	closer func()
}

// NewIPSet creates an IPSet manager for the given table name. It opens a
// netlink socket and probes the kernel's ipset protocol once; when that
// fails (or EnvBackend is "exec") the set is driven through exec for the
// lifetime of the value. Close releases the socket.
func NewIPSet(name string, opts ...Option) *IPSet {
	o := buildOptions(opts)
	s := &IPSet{Name: name}
	if forceExec() {
		return s
	}
	k, err := openIPSetKernel()
	if err != nil {
		o.logger.Info("ipset: netlink unavailable, using exec", "error", err)
		return s
	}
	s.useKernel(k, o.logger)
	return s
}

// useKernel installs a netlink backend on top of the exec one.
func (s *IPSet) useKernel(k ipsetKernel, logger *slog.Logger) {
	s.nl = newFallback[IPSetBackend]("ipset", &netlinkIPSet{name: s.Name, k: k}, logger)
	s.closer = k.Close
}

// Backend reports which backend calls currently go to.
func (s *IPSet) Backend() string { return s.nl.backend() }

// Close releases the netlink socket, if any. The IPSet keeps working
// through exec afterwards.
func (s *IPSet) Close() {
	if s.nl != nil {
		s.nl.active.Store(false)
	}
	if s.closer != nil {
		s.closer()
		s.closer = nil
	}
}

func (s *IPSet) exec() IPSetBackend {
	return execIPSet{name: s.Name, run: platform.OrDefault(s.Runner)}
}

func (s *IPSet) do(op string, call func(IPSetBackend) error) error {
	if s.nl == nil {
		return call(s.exec())
	}
	return s.nl.do(op, s.exec(), call)
}

// EnsureTable creates the ipset table if it doesn't exist.
func (s *IPSet) EnsureTable(ctx context.Context) error {
	return s.do("ensure", func(b IPSetBackend) error { return b.Ensure(ctx) })
}

// Flush removes all entries from the table.
func (s *IPSet) Flush(ctx context.Context) error {
	return s.do("flush", func(b IPSetBackend) error { return b.Flush(ctx) })
}

// Add adds an IP or CIDR to the table; already present is not an error.
func (s *IPSet) Add(ctx context.Context, entry string) error {
	return s.do("add", func(b IPSetBackend) error { return b.Add(ctx, entry) })
}

// Del removes an IP or CIDR from the table; already absent is not an error.
func (s *IPSet) Del(ctx context.Context, entry string) error {
	return s.do("del", func(b IPSetBackend) error { return b.Del(ctx, entry) })
}

// AddBatch adds every member in one call (one `ipset restore` process on
// exec, one socket on netlink). Members already present are not errors. Not
// transactional: on an error a prefix of the members is applied, so callers
// fall back to per-member calls to learn the exact state.
func (s *IPSet) AddBatch(ctx context.Context, members []string) error {
	if len(members) == 0 {
		return nil
	}
	return s.do("add-batch", func(b IPSetBackend) error { return b.AddBatch(ctx, members) })
}

// DelBatch removes every member in one call; see AddBatch.
func (s *IPSet) DelBatch(ctx context.Context, members []string) error {
	if len(members) == 0 {
		return nil
	}
	return s.do("del-batch", func(b IPSetBackend) error { return b.DelBatch(ctx, members) })
}

// List returns all entries in the table.
func (s *IPSet) List(ctx context.Context) ([]string, error) {
	var out []string
	err := s.do("list", func(b IPSetBackend) error {
		var err error
		out, err = b.List(ctx)
		return err
	})
	return out, err
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
	return s.do("destroy", func(b IPSetBackend) error { return b.Destroy(ctx) })
}
