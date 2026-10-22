package netfilter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/egorlepa/netshunt/internal/platform"
)

// ConntrackBackend drops conntrack flows by original destination.
type ConntrackBackend interface {
	// FlushDst deletes every IPv4 flow whose original destination lies in
	// any of members (addresses or CIDRs). Best effort: an error is worth a
	// debug line, the flows that could be deleted are gone.
	FlushDst(ctx context.Context, members []string) error
}

// Conntrack deletes conntrack flows so connections to addresses that just
// entered or left the ipset reopen on the new path. NewConntrack uses
// netlink (one table dump per call, whatever the number of members) when the
// kernel allows it and the conntrack binary (one process per member)
// otherwise; a zero Conntrack{Runner} literal always uses exec.
type Conntrack struct {
	// Runner executes conntrack for the exec backend; nil means
	// platform.DefaultRunner.
	Runner platform.Runner

	nl     *fallback[ConntrackBackend] // nil: exec only
	closer func()
}

// NewConntrack opens a netlink socket and probes it with one table dump;
// when that fails (or EnvBackend is "exec") flows are deleted through exec.
func NewConntrack(opts ...Option) *Conntrack {
	o := buildOptions(opts)
	c := &Conntrack{}
	if forceExec() {
		return c
	}
	k, err := openConntrackKernel()
	if err != nil {
		o.logger.Info("conntrack: netlink unavailable, using exec", "error", err)
		return c
	}
	c.useKernel(k, o.logger)
	return c
}

func (c *Conntrack) useKernel(k conntrackKernel, logger *slog.Logger) {
	c.nl = newFallback[ConntrackBackend]("conntrack", &netlinkConntrack{k: k}, logger)
	c.closer = k.Close
}

// Backend reports which backend calls currently go to.
func (c *Conntrack) Backend() string { return c.nl.backend() }

// Close releases the netlink socket, if any; exec is used afterwards.
func (c *Conntrack) Close() {
	if c.nl != nil {
		c.nl.active.Store(false)
	}
	if c.closer != nil {
		c.closer()
		c.closer = nil
	}
}

// FlushDst deletes the flows whose original destination lies in any of
// members. No members, no call.
func (c *Conntrack) FlushDst(ctx context.Context, members []string) error {
	if len(members) == 0 {
		return nil
	}
	call := func(b ConntrackBackend) error { return b.FlushDst(ctx, members) }
	exec := execConntrack{run: platform.OrDefault(c.Runner)}
	if c.nl == nil {
		return call(exec)
	}
	return c.nl.do("flush", exec, call)
}

// execConntrack runs `conntrack -D --orig-dst` once per member.
type execConntrack struct {
	run platform.Runner
}

func (c execConntrack) FlushDst(ctx context.Context, members []string) error {
	failed := 0
	var first error
	for _, m := range members {
		if err := c.run.RunSilent(ctx, "conntrack", conntrackDeleteArgs(m)...); err != nil {
			failed++
			if first == nil {
				first = err
			}
		}
	}
	if failed > 0 {
		// conntrack exits non-zero when nothing matched: the common case.
		return fmt.Errorf("conntrack -D non-zero for %d of %d members (likely no matches): %w", failed, len(members), first)
	}
	return nil
}

// conntrackDeleteArgs builds the conntrack -D arguments for an IP or CIDR.
func conntrackDeleteArgs(member string) []string {
	if p, err := netip.ParsePrefix(member); err == nil {
		mask := net.IP(net.CIDRMask(p.Bits(), 32)).String()
		return []string{"-D", "--orig-dst", p.Masked().Addr().String(), "--mask-dst", mask}
	}
	return []string{"-D", "--orig-dst", member}
}

// conntrackKernel is the netlink surface netlinkConntrack drives. Faked in
// tests.
type conntrackKernel interface {
	// DeleteOrigDst dumps the IPv4 table once and deletes every flow whose
	// original destination satisfies match. Returns the number deleted.
	DeleteOrigDst(match func(netip.Addr) bool) (int, error)
	Close()
}

// netlinkConntrack is the ConntrackBackend over a conntrackKernel.
type netlinkConntrack struct {
	k conntrackKernel
}

func (c *netlinkConntrack) FlushDst(ctx context.Context, members []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	set, parseErr := newPrefixSet(members)
	if set.empty() {
		return parseErr
	}
	_, err := c.k.DeleteOrigDst(set.contains)
	if isTransport(err) {
		return err // retried through exec, members and all
	}
	return errors.Join(parseErr, err)
}

// prefixSet answers "is this address inside any member" for a batch of
// members: hosts by map lookup, networks by a scan (a handful at most, a few
// hundred for a large static shunt).
type prefixSet struct {
	hosts map[netip.Addr]struct{}
	nets  []netip.Prefix
}

// newPrefixSet parses members (addresses or CIDRs); unparsable ones are
// reported and skipped.
func newPrefixSet(members []string) (prefixSet, error) {
	s := prefixSet{hosts: make(map[netip.Addr]struct{}, len(members))}
	var errs []error
	for _, m := range members {
		p, err := parseMember(m)
		if err != nil {
			errs = append(errs, fmt.Errorf("conntrack member %q: %w", m, err))
			continue
		}
		if p.Bits() == 32 {
			s.hosts[p.Addr()] = struct{}{}
		} else {
			s.nets = append(s.nets, p)
		}
	}
	return s, errors.Join(errs...)
}

func (s prefixSet) empty() bool { return len(s.hosts) == 0 && len(s.nets) == 0 }

func (s prefixSet) contains(a netip.Addr) bool {
	a = a.Unmap()
	if _, ok := s.hosts[a]; ok {
		return true
	}
	for _, p := range s.nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// rawConntrack is the real conntrackKernel: ctnetlink requests on one
// persistent NETLINK_NETFILTER socket. The dump is parsed down to the
// original destination only; the library's full flow parser costs about
// 50 us per flow on the router and would make a one-IP flush slower than
// the conntrack binary.
type rawConntrack struct {
	sh *nl.SocketHandle
}

// openConntrackKernel opens the socket and probes it with one dump that
// deletes nothing: the dump has to work on this kernel (Keenetic adds
// non-standard attributes), not only the socket.
func openConntrackKernel() (*rawConntrack, error) {
	s, err := nl.GetNetlinkSocketAt(netns.None(), netns.None(), unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	k := &rawConntrack{sh: &nl.SocketHandle{Socket: s}}
	err = setTimeouts(s)
	if err == nil {
		_, err = k.DeleteOrigDst(func(netip.Addr) bool { return false })
	}
	if err != nil {
		k.Close()
		return nil, err
	}
	return k, nil
}

func (k *rawConntrack) Close() { k.sh.Close() }

func (k *rawConntrack) request(msgType, flags int) *nl.NetlinkRequest {
	req := nl.NewNetlinkRequest((unix.NFNL_SUBSYS_CTNETLINK<<8)|msgType, flags)
	req.Sockets = map[int]*nl.SocketHandle{unix.NETLINK_NETFILTER: k.sh}
	req.AddData(&nl.Nfgenmsg{NfgenFamily: unix.AF_INET, Version: nl.NFNETLINK_V0})
	return req
}

// DeleteOrigDst dumps the IPv4 table once, then deletes every matching flow
// by its original tuple, zone and id (so a flow re-created with the same
// tuple in between is left alone). A flow that vanished meanwhile counts as
// deleted. An interrupted dump is not an error: what was seen is deleted.
func (k *rawConntrack) DeleteOrigDst(match func(netip.Addr) bool) (int, error) {
	var victims [][]byte
	err := guard(func() error {
		return k.request(nl.IPCTNL_MSG_CT_GET, unix.NLM_F_DUMP).ExecuteIter(unix.NETLINK_NETFILTER, 0, func(msg []byte) bool {
			if key, ok := flowDeleteKey(msg, match); ok {
				victims = append(victims, key)
			}
			return true
		})
	})
	if err != nil && !errors.Is(err, nl.ErrDumpInterrupted) {
		return 0, err
	}

	deleted, failed := 0, 0
	var first error
	for _, key := range victims {
		req := k.request(nl.IPCTNL_MSG_CT_DELETE, unix.NLM_F_ACK)
		req.AddRawData(key)
		err := guard(func() error {
			_, err := req.Execute(unix.NETLINK_NETFILTER, 0)
			return err
		})
		switch {
		case err == nil || errors.Is(err, syscall.ENOENT):
			deleted++
		case isTransport(err):
			return deleted, err
		default:
			failed++
			if first == nil {
				first = err
			}
		}
	}
	if failed > 0 {
		return deleted, fmt.Errorf("conntrack: %d of %d flow deletes failed: %w", failed, len(victims), first)
	}
	return deleted, nil
}

// flowDeleteKey reads one ctnetlink dump message (nfgenmsg + attributes).
// When the IPv4 original destination satisfies match it returns the
// attributes that identify the flow for IPCTNL_MSG_CT_DELETE: the original
// tuple, the zone and the id, copied verbatim.
func flowDeleteKey(msg []byte, match func(netip.Addr) bool) ([]byte, bool) {
	if len(msg) < 4 {
		return nil, false
	}
	attrs := msg[4:]
	orig, ok := findAttr(attrs, nl.CTA_TUPLE_ORIG)
	if !ok {
		return nil, false
	}
	ip, ok := findAttr(orig.val, nl.CTA_TUPLE_IP)
	if !ok {
		return nil, false
	}
	dst, ok := findAttr(ip.val, nl.CTA_IP_V4_DST)
	if !ok || len(dst.val) != 4 {
		return nil, false
	}
	if !match(netip.AddrFrom4([4]byte(dst.val))) {
		return nil, false
	}
	key := appendAligned(nil, orig.raw)
	for _, typ := range []uint16{nl.CTA_ZONE, nl.CTA_ID} {
		if a, ok := findAttr(attrs, typ); ok {
			key = appendAligned(key, a.raw)
		}
	}
	return key, true
}
