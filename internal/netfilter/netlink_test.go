package netfilter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/egorlepa/netshunt/internal/platform/runnertest"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeIPSetKernel is an in-memory ipsetKernel. err, when set, answers every
// call (after recording it).
type fakeIPSetKernel struct {
	mu      sync.Mutex
	exists  bool
	members map[netip.Prefix]struct{}
	calls   []string
	err     error
	// headerErr answers Header when the set is missing.
	headerErr error
	created   string
}

func newFakeIPSetKernel() *fakeIPSetKernel {
	return &fakeIPSetKernel{exists: true, members: map[netip.Prefix]struct{}{}, headerErr: syscall.ENOENT}
}

func (f *fakeIPSetKernel) rec(c string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
	return f.err
}

func (f *fakeIPSetKernel) Header(name string) error {
	if err := f.rec("header " + name); err != nil {
		return err
	}
	if !f.exists {
		return f.headerErr
	}
	return nil
}

func (f *fakeIPSetKernel) Create(name string, hs, me uint32) error {
	if err := f.rec("create " + name); err != nil {
		return err
	}
	f.exists = true
	f.created = fmt.Sprintf("%s hashsize %d maxelem %d", name, hs, me)
	return nil
}

func (f *fakeIPSetKernel) Add(name string, p netip.Prefix) error {
	if err := f.rec("add " + p.String()); err != nil {
		return err
	}
	f.members[p] = struct{}{}
	return nil
}

func (f *fakeIPSetKernel) Del(name string, p netip.Prefix) error {
	if err := f.rec("del " + p.String()); err != nil {
		return err
	}
	delete(f.members, p)
	return nil
}

func (f *fakeIPSetKernel) List(name string) ([]netip.Prefix, error) {
	if err := f.rec("list"); err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for p := range f.members {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return out, nil
}

func (f *fakeIPSetKernel) Flush(string) error   { return f.rec("flush") }
func (f *fakeIPSetKernel) Destroy(string) error { return f.rec("destroy") }
func (f *fakeIPSetKernel) Close()               {}

func (f *fakeIPSetKernel) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func netlinkSet(k ipsetKernel, run *runnertest.Fake) *IPSet {
	s := &IPSet{Name: "bypass", Runner: run}
	s.useKernel(k, discard())
	return s
}

func TestMemberCanonicalisation(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4":     "1.2.3.4/32",
		"1.2.3.4/32":  "1.2.3.4/32",
		"10.1.2.3/16": "10.1.0.0/16",
		"0.0.0.0/0":   "0.0.0.0/0",
	} {
		p, err := parseMember(in)
		if err != nil || p.String() != want {
			t.Errorf("parseMember(%q) = %v, %v, want %s", in, p, err, want)
		}
	}
	for _, bad := range []string{"", "nope", "2001:db8::1", "2001:db8::/32", "1.2.3.4/33"} {
		if _, err := parseMember(bad); err == nil {
			t.Errorf("parseMember(%q) accepted", bad)
		}
	}
	for in, want := range map[string]string{
		"1.2.3.4/32":  "1.2.3.4",
		"10.0.0.0/8":  "10.0.0.0/8",
		"10.1.0.0/31": "10.1.0.0/31",
	} {
		if got := formatMember(netip.MustParsePrefix(in)); got != want {
			t.Errorf("formatMember(%s) = %s, want %s", in, got, want)
		}
	}
	// Listed entries: hash:net reports the cidr; 0 or a 16-byte IP still
	// read as IPv4.
	cases := []struct {
		ip   net.IP
		cidr uint8
		want string
	}{
		{net.IPv4(1, 2, 3, 4).To4(), 32, "1.2.3.4"},
		{net.IPv4(1, 2, 3, 4), 32, "1.2.3.4"},
		{net.IPv4(10, 1, 2, 3).To4(), 16, "10.1.0.0/16"},
		{net.IPv4(9, 9, 9, 9).To4(), 0, "9.9.9.9"},
	}
	for _, c := range cases {
		p, ok := entryPrefix(c.ip, c.cidr)
		if !ok || formatMember(p) != c.want {
			t.Errorf("entryPrefix(%v,%d) = %v,%v, want %s", c.ip, c.cidr, p, ok, c.want)
		}
	}
	if _, ok := entryPrefix(net.ParseIP("2001:db8::1"), 128); ok {
		t.Error("entryPrefix accepted IPv6")
	}
}

func TestClassify(t *testing.T) {
	transport := []error{
		syscall.EBADF, syscall.EPROTO, syscall.EOPNOTSUPP, syscall.EPERM, syscall.ENOBUFS,
		syscall.EAGAIN, fmt.Errorf("wrapped: %w", syscall.ENOTSOCK), net.ErrClosed,
		errors.New("write netlink: use of closed file"),
	}
	for _, err := range transport {
		if !isTransport(classify(err)) {
			t.Errorf("%v not classified as transport", err)
		}
	}
	kernel := []error{
		syscall.ENOENT, syscall.EEXIST, syscall.EINVAL, syscall.ENOMEM,
		nl.IPSetError(nl.IPSET_ERR_EXIST), nl.IPSetError(nl.IPSET_ERR_PROTOCOL),
		fmt.Errorf("ipset add bypass 1.2.3.4: %w", nl.IPSetError(nl.IPSET_ERR_EXIST)),
		netlink.ErrDumpInterrupted, errors.New("failed to delete 2 conntrack flows"),
	}
	for _, err := range kernel {
		if isTransport(classify(err)) {
			t.Errorf("%v classified as transport", err)
		}
	}
	if classify(nil) != nil {
		t.Error("classify(nil) != nil")
	}
	err := guard(func() error { panic("interface conversion") })
	if !isTransport(err) {
		t.Errorf("panic not turned into a transport error: %v", err)
	}
}

func TestNetlinkIPSetEnsure(t *testing.T) {
	ctx := context.Background()

	k := newFakeIPSetKernel()
	if err := (&netlinkIPSet{name: "bypass", k: k}).Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	if got := k.callList(); !slices.Equal(got, []string{"header bypass"}) {
		t.Fatalf("existing set: calls = %v", got)
	}

	k = newFakeIPSetKernel()
	k.exists = false
	if err := (&netlinkIPSet{name: "bypass", k: k}).Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	if k.created != "bypass hashsize 16384 maxelem 262144" {
		t.Fatalf("created = %q", k.created)
	}

	k = newFakeIPSetKernel()
	k.err = classify(syscall.EBADF)
	if err := (&netlinkIPSet{name: "bypass", k: k}).Ensure(ctx); !isTransport(err) {
		t.Fatalf("transport failure on header: err = %v", err)
	}
	if got := k.callList(); !slices.Equal(got, []string{"header bypass"}) {
		t.Fatalf("broken transport must not try to create: %v", got)
	}
}

func TestNetlinkIPSetMembers(t *testing.T) {
	ctx := context.Background()
	k := newFakeIPSetKernel()
	s := netlinkSet(k, runnertest.New())

	if err := s.Add(ctx, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddBatch(ctx, []string{"10.1.2.3/16", "5.6.7.8/32"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"1.2.3.4", "5.6.7.8", "10.1.0.0/16"}; !slices.Equal(got, want) {
		t.Fatalf("List = %v, want %v", got, want)
	}
	if err := s.DelBatch(ctx, []string{"5.6.7.8", "10.1.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Del(ctx, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Count(ctx); n != 0 {
		t.Fatalf("Count = %d after deleting everything", n)
	}

	// A bad member in a batch stops it there (restore semantics) without
	// touching the kernel for it; the error is not a transport failure.
	err = s.AddBatch(ctx, []string{"7.7.7.7", "garbage", "8.8.8.8"})
	if err == nil || isTransport(err) {
		t.Fatalf("bad member: err = %v", err)
	}
	if slices.Contains(k.callList(), "add 8.8.8.8/32") {
		t.Fatal("batch went on after the failing member")
	}
	if s.Backend() != BackendNetlink {
		t.Fatal("a member error switched the backend")
	}

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.Del(cctx, "7.7.7.7"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ctx: err = %v", err)
	}
}

func TestIPSetFallsBackToExecOnTransportError(t *testing.T) {
	ctx := context.Background()
	k := newFakeIPSetKernel()
	k.err = classify(syscall.EBADF)
	run := runnertest.New()
	s := netlinkSet(k, run)

	if s.Backend() != BackendNetlink {
		t.Fatal("not on netlink initially")
	}
	if err := s.Add(ctx, "1.2.3.4"); err != nil {
		t.Fatalf("Add after fallback: %v", err)
	}
	if got := run.Calls(); !slices.Equal(got, []string{"ipset add bypass 1.2.3.4 -exist"}) {
		t.Fatalf("exec calls = %v, want the failed add retried once", got)
	}
	if s.Backend() != BackendExec {
		t.Fatal("backend not switched to exec")
	}
	if err := s.AddBatch(ctx, []string{"1.1.1.1", "2.2.2.2"}); err != nil {
		t.Fatal(err)
	}
	if n := len(k.callList()); n != 1 {
		t.Fatalf("netlink called %d times, want only the first failing call", n)
	}
	if got := run.Inputs(); !slices.Equal(got, []string{"add bypass 1.1.1.1\nadd bypass 2.2.2.2\n"}) {
		t.Fatalf("restore input = %q", got)
	}
}

func TestIPSetKernelErrorIsReturnedNotRetried(t *testing.T) {
	k := newFakeIPSetKernel()
	k.err = nl.IPSetError(nl.IPSET_ERR_PROTOCOL + 100) // e.g. "set is full"
	run := runnertest.New()
	s := netlinkSet(k, run)
	if err := s.Add(context.Background(), "1.2.3.4"); err == nil {
		t.Fatal("kernel error swallowed")
	}
	if len(run.Calls()) != 0 || s.Backend() != BackendNetlink {
		t.Fatalf("kernel error fell back to exec: calls=%v backend=%s", run.Calls(), s.Backend())
	}
}

func TestIPSetFallbackListRetriesThroughExec(t *testing.T) {
	k := newFakeIPSetKernel()
	k.err = &transportError{errors.New("panic: boom")}
	run := runnertest.New()
	run.On("ipset list bypass -output plain", "Name: bypass\nMembers:\n1.2.3.4\n", nil)
	s := netlinkSet(k, run)
	got, err := s.List(context.Background())
	if err != nil || !slices.Equal(got, []string{"1.2.3.4"}) {
		t.Fatalf("List = %v, %v", got, err)
	}
}

func TestForceExecEnv(t *testing.T) {
	t.Setenv(EnvBackend, "exec")
	if s := NewIPSet("bypass", WithLogger(discard())); s.Backend() != BackendExec {
		t.Fatal("NETSHUNT_NETFILTER=exec ignored by NewIPSet")
	}
	if c := NewConntrack(WithLogger(discard())); c.Backend() != BackendExec {
		t.Fatal("NETSHUNT_NETFILTER=exec ignored by NewConntrack")
	}
}

// fakeConntrackKernel deletes from an in-memory list of original
// destinations.
type fakeConntrackKernel struct {
	flows []netip.Addr
	err   error
	calls int
}

func (f *fakeConntrackKernel) DeleteOrigDst(match func(netip.Addr) bool) (int, error) {
	f.calls++
	if f.err != nil {
		return 0, f.err
	}
	n := 0
	f.flows = slices.DeleteFunc(f.flows, func(a netip.Addr) bool {
		if match(a) {
			n++
			return true
		}
		return false
	})
	return n, nil
}

func (f *fakeConntrackKernel) Close() {}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestPrefixSet(t *testing.T) {
	set, err := newPrefixSet([]string{"1.2.3.4", "10.0.0.0/8", "192.168.1.0/24", "bogus"})
	if err == nil {
		t.Fatal("bogus member not reported")
	}
	for a, want := range map[string]bool{
		"1.2.3.4": true, "1.2.3.5": false, "10.200.0.1": true, "11.0.0.1": false,
		"192.168.1.255": true, "192.168.2.1": false, "::ffff:10.0.0.1": true,
	} {
		if got := set.contains(netip.MustParseAddr(a)); got != want {
			t.Errorf("contains(%s) = %v, want %v", a, got, want)
		}
	}
}

// ctMessage builds a ctnetlink dump message like the router's: nfgenmsg,
// original and reply tuples, status, id, optionally a zone, and a
// Keenetic-specific attribute (type 25) the parser must skip.
func ctMessage(src, dst string, id uint32, zone bool) (msg, orig, zoneAttr, idAttr []byte) {
	tuple := func(typ int, s, d string) *nl.RtAttr {
		t := nl.NewRtAttr(typ|int(nl.NLA_F_NESTED), nil)
		ip := t.AddRtAttr(nl.CTA_TUPLE_IP|int(nl.NLA_F_NESTED), nil)
		ip.AddRtAttr(nl.CTA_IP_V4_SRC, net.ParseIP(s).To4())
		ip.AddRtAttr(nl.CTA_IP_V4_DST, net.ParseIP(d).To4())
		proto := t.AddRtAttr(nl.CTA_TUPLE_PROTO|int(nl.NLA_F_NESTED), nil)
		proto.AddRtAttr(nl.CTA_PROTO_NUM, []byte{6})
		proto.AddRtAttr(nl.CTA_PROTO_SRC_PORT, []byte{0x9c, 0x40})
		proto.AddRtAttr(nl.CTA_PROTO_DST_PORT, []byte{0x01, 0xbb})
		return t
	}
	be32 := func(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }
	orig = tuple(nl.CTA_TUPLE_ORIG, src, dst).Serialize()
	msg = append([]byte{unix.AF_INET, 0, 0, 0}, orig...)
	msg = append(msg, tuple(nl.CTA_TUPLE_REPLY, dst, src).Serialize()...)
	msg = append(msg, nl.NewRtAttr(nl.CTA_STATUS|int(nl.NLA_F_NET_BYTEORDER), be32(0x18e)).Serialize()...)
	ndm := nl.NewRtAttr(25|int(nl.NLA_F_NESTED), nil)
	ndm.AddRtAttr(1, []byte{1, 2, 3})
	msg = append(msg, ndm.Serialize()...)
	idAttr = nl.NewRtAttr(nl.CTA_ID|int(nl.NLA_F_NET_BYTEORDER), be32(id)).Serialize()
	msg = append(msg, idAttr...)
	if zone {
		zoneAttr = nl.NewRtAttr(nl.CTA_ZONE|int(nl.NLA_F_NET_BYTEORDER), []byte{0, 7}).Serialize()
		msg = append(msg, zoneAttr...)
	}
	return msg, orig, zoneAttr, idAttr
}

func TestFlowDeleteKey(t *testing.T) {
	set, _ := newPrefixSet([]string{"10.0.0.0/8", "1.2.3.4"})

	msg, orig, _, id := ctMessage("192.168.1.50", "10.1.2.3", 42, false)
	key, ok := flowDeleteKey(msg, set.contains)
	if !ok {
		t.Fatal("flow to 10.1.2.3 not matched by 10.0.0.0/8")
	}
	if want := slices.Concat(orig, id); !slices.Equal(key, want) {
		t.Fatalf("delete key = %x, want orig tuple + id %x", key, want)
	}

	msg, orig, zone, id := ctMessage("192.168.1.50", "1.2.3.4", 7, true)
	key, ok = flowDeleteKey(msg, set.contains)
	if !ok || !slices.Equal(key, slices.Concat(orig, zone, id)) {
		t.Fatalf("zoned flow: key = %x, ok = %v", key, ok)
	}

	// The source is in a member, the destination is not: no match. The
	// reply tuple (destination = our source) must not be read either.
	msg, _, _, _ = ctMessage("10.1.1.1", "8.8.8.8", 1, false)
	if _, ok := flowDeleteKey(msg, set.contains); ok {
		t.Fatal("matched on the source / reply tuple")
	}
	for _, bad := range [][]byte{nil, {2, 0, 0}, {2, 0, 0, 0, 0xff, 0xff}} {
		if _, ok := flowDeleteKey(bad, set.contains); ok {
			t.Fatalf("malformed message %x matched", bad)
		}
	}
	if len(key)%4 != 0 {
		t.Fatal("delete key not 4-byte aligned")
	}
}

func TestNetlinkConntrackOneDumpPerBatch(t *testing.T) {
	k := &fakeConntrackKernel{flows: addrs("1.2.3.4", "10.1.1.1", "10.2.2.2", "8.8.8.8", "1.2.3.4")}
	c := &Conntrack{}
	c.useKernel(k, discard())
	if err := c.FlushDst(context.Background(), []string{"1.2.3.4", "10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if k.calls != 1 {
		t.Fatalf("kernel calls = %d, want 1 for the whole batch", k.calls)
	}
	if !slices.Equal(k.flows, addrs("8.8.8.8")) {
		t.Fatalf("flows left = %v", k.flows)
	}
	if err := c.FlushDst(context.Background(), nil); err != nil || k.calls != 1 {
		t.Fatal("empty batch reached the kernel")
	}
}

func TestConntrackFallsBackToExecOnTransportError(t *testing.T) {
	k := &fakeConntrackKernel{err: classify(syscall.EPROTO)}
	run := runnertest.New()
	c := &Conntrack{Runner: run}
	c.useKernel(k, discard())
	if err := c.FlushDst(context.Background(), []string{"1.2.3.4", "10.1.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"conntrack -D --orig-dst 1.2.3.4",
		"conntrack -D --orig-dst 10.1.0.0 --mask-dst 255.255.0.0",
	}
	if got := run.Calls(); !slices.Equal(got, want) {
		t.Fatalf("exec calls = %v, want %v", got, want)
	}
	if c.Backend() != BackendExec {
		t.Fatal("backend not switched")
	}
	_ = c.FlushDst(context.Background(), []string{"5.5.5.5"})
	if k.calls != 1 {
		t.Fatalf("netlink called again after the switch: %d", k.calls)
	}
}

func TestExecConntrackReportsNonZero(t *testing.T) {
	run := runnertest.New()
	run.On("conntrack -D --orig-dst 1.2.3.4", "", runnertest.ErrScripted)
	c := &Conntrack{Runner: run}
	err := c.FlushDst(context.Background(), []string{"1.2.3.4", "5.6.7.8"})
	if err == nil || !errors.Is(err, runnertest.ErrScripted) {
		t.Fatalf("err = %v", err)
	}
	if len(run.Calls()) != 2 {
		t.Fatalf("calls = %v: one failure must not stop the rest", run.Calls())
	}
}
