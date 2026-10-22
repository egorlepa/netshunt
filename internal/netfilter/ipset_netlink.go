package netfilter

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// ipsetKernel is the netlink surface netlinkIPSet drives: one IPv4 hash:net
// set addressed by name, members as prefixes. Faked in tests.
type ipsetKernel interface {
	// Header returns nil when the set exists.
	Header(name string) error
	Create(name string, hashSize, maxElem uint32) error
	// Add and Del have -exist semantics: no error for present/absent.
	Add(name string, p netip.Prefix) error
	Del(name string, p netip.Prefix) error
	List(name string) ([]netip.Prefix, error)
	Flush(name string) error
	Destroy(name string) error
	Close()
}

// netlinkIPSet is the IPSetBackend over an ipsetKernel. It converts members
// between the `ipset list` string form and prefixes; the kernel calls are
// in-process, so a batch is a loop of acknowledged single calls.
type netlinkIPSet struct {
	name string
	k    ipsetKernel
}

// Ensure mirrors the exec backend: any answer other than "exists" (except a
// broken transport) leads to a create attempt.
func (s *netlinkIPSet) Ensure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := s.k.Header(s.name)
	if err == nil || isTransport(err) {
		return err
	}
	if err := s.k.Create(s.name, hashSizeN, maxElemN); err != nil {
		return fmt.Errorf("ipset create %s: %w", s.name, err)
	}
	return nil
}

func (s *netlinkIPSet) Add(ctx context.Context, member string) error {
	return s.apply(ctx, "add", s.k.Add, member)
}

func (s *netlinkIPSet) Del(ctx context.Context, member string) error {
	return s.apply(ctx, "del", s.k.Del, member)
}

func (s *netlinkIPSet) AddBatch(ctx context.Context, members []string) error {
	for _, m := range members {
		if err := s.apply(ctx, "add", s.k.Add, m); err != nil {
			return err
		}
	}
	return nil
}

func (s *netlinkIPSet) DelBatch(ctx context.Context, members []string) error {
	for _, m := range members {
		if err := s.apply(ctx, "del", s.k.Del, m); err != nil {
			return err
		}
	}
	return nil
}

func (s *netlinkIPSet) apply(ctx context.Context, op string, fn func(string, netip.Prefix) error, member string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := parseMember(member)
	if err != nil {
		return fmt.Errorf("ipset %s %s %s: %w", op, s.name, member, err)
	}
	if err := fn(s.name, p); err != nil {
		return fmt.Errorf("ipset %s %s %s: %w", op, s.name, member, err)
	}
	return nil
}

func (s *netlinkIPSet) List(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ps, err := s.k.List(s.name)
	if err != nil {
		return nil, fmt.Errorf("ipset list: %w", err)
	}
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = formatMember(p)
	}
	return out, nil
}

func (s *netlinkIPSet) Flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.k.Flush(s.name)
}

func (s *netlinkIPSet) Destroy(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.k.Destroy(s.name)
}

// parseMember reads an IPv4 address or CIDR into a masked prefix; a bare
// address is a /32.
func parseMember(v string) (netip.Prefix, error) {
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return netip.Prefix{}, err
		}
		if !p.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("not an IPv4 network: %s", v)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Prefix{}, err
	}
	if !a.Is4() {
		return netip.Prefix{}, fmt.Errorf("not an IPv4 address: %s", v)
	}
	return netip.PrefixFrom(a, 32), nil
}

// formatMember prints a prefix the way `ipset list` does for hash:net: a
// bare address for a /32, network/bits otherwise.
func formatMember(p netip.Prefix) string {
	if p.Bits() == 32 {
		return p.Addr().String()
	}
	return p.String()
}

// entryPrefix converts a listed hash:net entry. hash:net always reports the
// cidr; 0 is read as a host.
func entryPrefix(ip net.IP, cidr uint8) (netip.Prefix, bool) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	if !a.Is4() {
		return netip.Prefix{}, false
	}
	bits := int(cidr)
	if bits == 0 || bits > 32 {
		bits = 32
	}
	return netip.PrefixFrom(a, bits).Masked(), true
}

// netlinkTimeout bounds every send and receive on the netlink sockets, so a
// kernel that never answers fails the call (EAGAIN, a transport error)
// instead of hanging the daemon.
const netlinkTimeout = 5 * time.Second

// setTimeouts applies netlinkTimeout to a socket the library did not open.
func setTimeouts(s *nl.NetlinkSocket) error {
	tv := unix.NsecToTimeval(netlinkTimeout.Nanoseconds())
	if err := s.SetSendTimeout(&tv); err != nil {
		return err
	}
	return s.SetReceiveTimeout(&tv)
}

// vishIPSet is the real ipsetKernel: vishvananda/netlink on one persistent
// NETLINK_NETFILTER socket for add/del/list/flush/destroy, plus a second
// socket for the requests the library does not offer (header, type
// revision, create with hashsize).
type vishIPSet struct {
	h   *netlink.Handle
	ctl *nl.SocketHandle
}

// openIPSetKernel opens the sockets and probes the kernel's ipset protocol.
func openIPSetKernel() (*vishIPSet, error) {
	h, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	if err := h.SetSocketTimeout(netlinkTimeout); err != nil {
		h.Close()
		return nil, err
	}
	s, err := nl.GetNetlinkSocketAt(netns.None(), netns.None(), unix.NETLINK_NETFILTER)
	if err != nil {
		h.Close()
		return nil, err
	}
	k := &vishIPSet{h: h, ctl: &nl.SocketHandle{Socket: s}}
	if err := setTimeouts(s); err != nil {
		k.Close()
		return nil, err
	}

	var proto, minProto uint8
	err = guard(func() error {
		var err error
		proto, minProto, err = h.IpsetProtocol()
		return err
	})
	if err == nil && (proto < nl.IPSET_PROTOCOL || minProto > nl.IPSET_PROTOCOL) {
		err = fmt.Errorf("kernel ipset protocol %d-%d, need %d", minProto, proto, nl.IPSET_PROTOCOL)
	}
	if err != nil {
		k.Close()
		return nil, err
	}
	return k, nil
}

func (k *vishIPSet) Close() {
	k.h.Close()
	k.ctl.Close()
}

func entryOf(p netip.Prefix) *netlink.IPSetEntry {
	// Replace drops NLM_F_EXCL: the kernel then ignores an add of a present
	// member and a del of an absent one, exactly like `ipset -exist`.
	return &netlink.IPSetEntry{IP: net.IP(p.Addr().AsSlice()), CIDR: uint8(p.Bits()), Replace: true}
}

func (k *vishIPSet) Add(name string, p netip.Prefix) error {
	return guard(func() error { return k.h.IpsetAdd(name, entryOf(p)) })
}

func (k *vishIPSet) Del(name string, p netip.Prefix) error {
	return guard(func() error { return k.h.IpsetDel(name, entryOf(p)) })
}

func (k *vishIPSet) List(name string) ([]netip.Prefix, error) {
	var res *netlink.IPSetResult
	err := guard(func() error {
		var err error
		res, err = k.h.IpsetList(name)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(res.Entries))
	for _, e := range res.Entries {
		if p, ok := entryPrefix(e.IP, e.CIDR); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func (k *vishIPSet) Flush(name string) error {
	return guard(func() error { return k.h.IpsetFlush(name) })
}

func (k *vishIPSet) Destroy(name string) error {
	return guard(func() error { return k.h.IpsetDestroy(name) })
}

// Header sends IPSET_CMD_HEADER: the set's name, type, revision and family,
// without members. ENOENT means the set does not exist.
func (k *vishIPSet) Header(name string) error {
	req := k.request(nl.IPSET_CMD_HEADER)
	req.AddData(nl.NewRtAttr(nl.IPSET_ATTR_SETNAME, nl.ZeroTerminated(name)))
	_, err := k.execute(req)
	return err
}

// Create sends IPSET_CMD_CREATE for an IPv4 hash:net with an explicit
// hashsize and maxelem, at the highest revision the kernel offers (what the
// ipset binary picks too). Without NLM_F_EXCL an existing identical set is
// not an error.
func (k *vishIPSet) Create(name string, hashSize, maxElem uint32) error {
	const typ = "hash:net"
	rev, err := k.typeRevision(typ)
	if err != nil {
		return err
	}
	req := k.request(nl.IPSET_CMD_CREATE)
	req.AddData(nl.NewRtAttr(nl.IPSET_ATTR_SETNAME, nl.ZeroTerminated(name)))
	req.AddData(nl.NewRtAttr(nl.IPSET_ATTR_TYPENAME, nl.ZeroTerminated(typ)))
	req.AddData(nl.NewRtAttr(nl.IPSET_ATTR_REVISION, nl.Uint8Attr(rev)))
	req.AddData(nl.NewRtAttr(nl.IPSET_ATTR_FAMILY, nl.Uint8Attr(unix.AF_INET)))
	data := nl.NewRtAttr(nl.IPSET_ATTR_DATA|int(nl.NLA_F_NESTED), nil)
	data.AddChild(&nl.Uint32Attribute{Type: nl.IPSET_ATTR_HASHSIZE | nl.NLA_F_NET_BYTEORDER, Value: hashSize})
	data.AddChild(&nl.Uint32Attribute{Type: nl.IPSET_ATTR_MAXELEM | nl.NLA_F_NET_BYTEORDER, Value: maxElem})
	req.AddData(data)
	_, err = k.execute(req)
	return err
}

// typeRevision asks the kernel (IPSET_CMD_TYPE) for the highest revision of
// an IPv4 set type.
func (k *vishIPSet) typeRevision(typ string) (uint8, error) {
	req := k.request(nl.IPSET_CMD_TYPE)
	req.AddData(nl.NewRtAttr(nl.IPSET_ATTR_TYPENAME, nl.ZeroTerminated(typ)))
	req.AddData(nl.NewRtAttr(nl.IPSET_ATTR_FAMILY, nl.Uint8Attr(unix.AF_INET)))
	msgs, err := k.execute(req)
	if err != nil {
		return 0, err
	}
	for _, msg := range msgs {
		if rev, ok := attrUint8(msg, nl.IPSET_ATTR_REVISION); ok {
			return rev, nil
		}
	}
	return 0, fmt.Errorf("ipset type %s: no revision in kernel answer", typ)
}

// request builds an ipset request bound to the control socket, the way the
// library builds its own (nfgenmsg + protocol attribute).
func (k *vishIPSet) request(cmd int) *nl.NetlinkRequest {
	req := nl.NewNetlinkRequest(cmd|(unix.NFNL_SUBSYS_IPSET<<8), nl.GetIpsetFlags(cmd))
	req.Sockets = map[int]*nl.SocketHandle{unix.NETLINK_NETFILTER: k.ctl}
	req.AddData(&nl.Nfgenmsg{NfgenFamily: uint8(unix.AF_NETLINK), Version: nl.NFNETLINK_V0})
	req.AddData(nl.NewRtAttr(nl.IPSET_ATTR_PROTOCOL, nl.Uint8Attr(nl.IPSET_PROTOCOL)))
	return req
}

// execute runs a request on the control socket; ipset-private errnos
// (>= 4096) become nl.IPSetError like in the library.
func (k *vishIPSet) execute(req *nl.NetlinkRequest) ([][]byte, error) {
	var msgs [][]byte
	err := guard(func() error {
		var err error
		msgs, err = req.Execute(unix.NETLINK_NETFILTER, 0)
		if errno, ok := err.(syscall.Errno); ok && int(errno) >= nl.IPSET_ERR_PRIVATE {
			err = nl.IPSetError(uintptr(errno))
		}
		return err
	})
	return msgs, err
}

// attrUint8 returns the first byte of the top-level attribute typ of an
// nfnetlink message (after the 4-byte nfgenmsg).
func attrUint8(msg []byte, typ uint16) (uint8, bool) {
	if len(msg) < 4 {
		return 0, false
	}
	a, ok := findAttr(msg[4:], typ)
	if !ok || len(a.val) == 0 {
		return 0, false
	}
	return a.val[0], true
}
