package netfilter

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The integration tests run against the real kernel and the ipset and
// conntrack binaries, on a scratch set. Never in CI: they need root and the
// router's kernel.
//
//	GOARCH=arm64 go test -c -o nlit ./internal/netfilter/
//	NETSHUNT_NETLINK_IT=1 ./nlit -test.run Integration -test.v
const (
	envIntegration = "NETSHUNT_NETLINK_IT"
	scratchSet     = "zz_nl_test"
	scratchRef     = "zz_nl_ref"
)

func needKernel(t *testing.T) {
	t.Helper()
	if os.Getenv(envIntegration) != "1" {
		t.Skipf("set %s=1 to run against the real kernel", envIntegration)
	}
}

func ipsetExec(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ipset", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ipset %v: %v: %s", args, err, out)
	}
	return string(out)
}

// headerLines keeps the lines of `ipset list -t` that describe the set's
// type and parameters.
func headerLines(out string) []string {
	var keep []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "Type:") || strings.HasPrefix(l, "Revision:") || strings.HasPrefix(l, "Header:") {
			keep = append(keep, l)
		}
	}
	return keep
}

func testMembers(n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		if i%5 == 0 {
			out = append(out, fmt.Sprintf("10.210.%d.%d", byte(i>>8), byte(i)))
		} else {
			out = append(out, fmt.Sprintf("10.%d.%d.0/24", 200+(i>>8), byte(i)))
		}
	}
	return out
}

func TestIntegrationIPSet(t *testing.T) {
	needKernel(t)
	ctx := context.Background()
	_ = exec.Command("ipset", "destroy", scratchSet).Run()
	_ = exec.Command("ipset", "destroy", scratchRef).Run()
	t.Cleanup(func() {
		_ = exec.Command("ipset", "destroy", scratchSet).Run()
		_ = exec.Command("ipset", "destroy", scratchRef).Run()
	})

	s := NewIPSet(scratchSet)
	defer s.Close()
	if s.Backend() != BackendNetlink {
		t.Fatalf("backend = %s", s.Backend())
	}

	start := time.Now()
	if err := s.EnsureTable(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("ensure (create) %v", time.Since(start))
	start = time.Now()
	if err := s.EnsureTable(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("ensure (exists) %v", time.Since(start))

	(&IPSet{Name: scratchRef}).EnsureTable(ctx) //nolint:errcheck // checked below
	got := headerLines(ipsetExec(t, "list", "-t", scratchSet))
	want := headerLines(ipsetExec(t, "list", "-t", scratchRef))
	t.Logf("netlink-created header: %v", got)
	if !slices.Equal(got, want) || len(got) != 3 {
		t.Fatalf("header %v differs from exec-created %v", got, want)
	}

	members := testMembers(2000)
	start = time.Now()
	if err := s.AddBatch(ctx, members); err != nil {
		t.Fatal(err)
	}
	t.Logf("add-batch n=%d %v", len(members), time.Since(start))
	if err := s.Add(ctx, members[0]); err != nil {
		t.Fatalf("re-add of a present member: %v", err)
	}

	start = time.Now()
	nlList, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("list n=%d %v", len(nlList), time.Since(start))
	exList, err := (&IPSet{Name: scratchSet}).List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(nlList)
	slices.Sort(exList)
	wantList := slices.Clone(members)
	slices.Sort(wantList)
	if !slices.Equal(nlList, exList) || !slices.Equal(nlList, wantList) {
		t.Fatalf("netlink list (%d) != exec list (%d) or members", len(nlList), len(exList))
	}

	start = time.Now()
	if err := s.DelBatch(ctx, members); err != nil {
		t.Fatal(err)
	}
	t.Logf("del-batch n=%d %v", len(members), time.Since(start))
	if err := s.Del(ctx, members[0]); err != nil {
		t.Fatalf("del of an absent member: %v", err)
	}
	if n, _ := (&IPSet{Name: scratchSet}).Count(ctx); n != 0 {
		t.Fatalf("exec count after deleting everything = %d", n)
	}

	start = time.Now()
	for i := range 100 {
		if err := s.Add(ctx, fmt.Sprintf("10.250.0.%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("single add x100 %v", time.Since(start))

	if err := s.Add(ctx, "2001:db8::1"); err == nil || isTransport(err) {
		t.Fatalf("IPv6 member: err = %v", err)
	}
	if err := (&netlinkIPSet{name: "zz_missing", k: s.nl.nl.(*netlinkIPSet).k}).Add(ctx, "1.2.3.4"); err == nil || isTransport(err) {
		t.Fatalf("missing set: err = %v (want a kernel error)", err)
	} else {
		t.Logf("missing set answer: %v", err)
	}
	if s.Backend() != BackendNetlink {
		t.Fatal("kernel errors switched the backend")
	}

	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Destroy(ctx); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("ipset", "list", "-n", scratchSet).CombinedOutput(); err == nil {
		t.Fatalf("set still exists after Destroy: %s", out)
	}
}

func TestIntegrationIPSetFallbackOnClosedSocket(t *testing.T) {
	needKernel(t)
	ctx := context.Background()
	_ = exec.Command("ipset", "destroy", scratchSet).Run()
	t.Cleanup(func() { _ = exec.Command("ipset", "destroy", scratchSet).Run() })

	k, err := openIPSetKernel()
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	k.ctl.Socket.Close() // header/create go through this socket
	s := &IPSet{Name: scratchSet}
	s.useKernel(k, discard())
	if err := s.EnsureTable(ctx); err != nil {
		t.Fatalf("EnsureTable did not fall back: %v", err)
	}
	if s.Backend() != BackendExec {
		t.Fatalf("backend = %s after a closed socket", s.Backend())
	}
	t.Logf("exec-created after fallback: %v", headerLines(ipsetExec(t, "list", "-t", scratchSet)))
}

func TestIntegrationConntrack(t *testing.T) {
	needKernel(t)
	ctx := context.Background()
	c := NewConntrack()
	defer c.Close()
	if c.Backend() != BackendNetlink {
		t.Fatalf("backend = %s", c.Backend())
	}

	h, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	flow := func(dst string) *netlink.ConntrackFlow {
		return &netlink.ConntrackFlow{
			FamilyType: unix.AF_INET,
			Forward:    netlink.IPTuple{SrcIP: net.ParseIP("192.0.2.10").To4(), DstIP: net.ParseIP(dst).To4(), Protocol: unix.IPPROTO_UDP, SrcPort: 40000, DstPort: 53},
			Reverse:    netlink.IPTuple{SrcIP: net.ParseIP(dst).To4(), DstIP: net.ParseIP("192.0.2.10").To4(), Protocol: unix.IPPROTO_UDP, SrcPort: 53, DstPort: 40000},
			TimeOut:    60,
		}
	}
	count := func(dst string) int {
		flows, err := h.ConntrackTableList(netlink.ConntrackTable, unix.AF_INET)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		want := netip.MustParseAddr(dst)
		for _, f := range flows {
			if a, ok := netip.AddrFromSlice(f.Forward.DstIP); ok && a.Unmap() == want {
				n++
			}
		}
		return n
	}
	a, b := "198.51.100.7", "198.51.100.200"
	created := true
	for _, d := range []string{a, b} {
		if err := h.ConntrackCreate(netlink.ConntrackTable, unix.AF_INET, flow(d)); err != nil {
			t.Logf("cannot create a test flow (%v): checking timings only", err)
			created = false
			break
		}
	}
	if created {
		t.Logf("created flows: a=%d b=%d", count(a), count(b))
		if err := c.FlushDst(ctx, []string{"198.51.100.0/25"}); err != nil {
			t.Fatal(err)
		}
		if count(a) != 0 || count(b) != 1 {
			t.Fatalf("after flushing 198.51.100.0/25: a=%d b=%d, want 0,1", count(a), count(b))
		}
		if err := c.FlushDst(ctx, []string{b}); err != nil {
			t.Fatal(err)
		}
		if count(b) != 0 {
			t.Fatal("host member did not delete its flow")
		}
	}

	var cidrs []string
	for i := range 319 {
		cidrs = append(cidrs, fmt.Sprintf("10.%d.%d.0/24", 250+i/256, byte(i)))
	}
	flows, _ := h.ConntrackTableList(netlink.ConntrackTable, unix.AF_INET)
	start := time.Now()
	if err := c.FlushDst(ctx, cidrs); err != nil {
		t.Fatal(err)
	}
	t.Logf("flush 319 cidrs over %d flows: %v", len(flows), time.Since(start))
	start = time.Now()
	for i := range 10 {
		if err := c.FlushDst(ctx, []string{fmt.Sprintf("10.249.0.%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("flush 1 ip x10: %v", time.Since(start))
	start = time.Now()
	for range 10 {
		_ = (&Conntrack{}).FlushDst(ctx, []string{"10.249.0.1"})
	}
	t.Logf("exec flush 1 ip x10: %v", time.Since(start))
}
