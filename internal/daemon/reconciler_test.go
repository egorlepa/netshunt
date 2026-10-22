package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	mdns "codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/dns"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/platform/runnertest"
	"github.com/egorlepa/netshunt/internal/shunt"
)

// fakeIPSet is the in-memory kernel ipset the tracker drives.
type fakeIPSet struct {
	mu      sync.Mutex
	members map[string]struct{}
	// onDel runs before every Del (outside the lock), e.g. to cancel ctx.
	onDel   func()
	flushes int
}

func newFakeIPSet() *fakeIPSet { return &fakeIPSet{members: map[string]struct{}{}} }

func (f *fakeIPSet) Add(ctx context.Context, e string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.members[e] = struct{}{}
	return nil
}

func (f *fakeIPSet) Del(ctx context.Context, e string) error {
	if f.onDel != nil {
		f.onDel()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.members, e)
	return nil
}

func (f *fakeIPSet) Flush(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushes++
	f.members = map[string]struct{}{}
	return nil
}

func (f *fakeIPSet) List(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for m := range f.members {
		out = append(out, m)
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeIPSet) list() []string {
	out, _ := f.List(context.Background())
	return out
}

// fakeMode records the routing calls the reconciler makes.
type fakeMode struct {
	mu         sync.Mutex
	reconciles int
	teardowns  int
	err        error // returned by Reconcile
}

func (m *fakeMode) Name() string { return "fake" }
func (m *fakeMode) Reconcile(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconciles++
	return m.err
}
func (m *fakeMode) TeardownRules(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.teardowns++
	return nil
}
func (m *fakeMode) IsActive(context.Context) (bool, error) { return true, nil }

type harness struct {
	t     *testing.T
	r     *Reconciler
	store *shunt.Store
	ipset *fakeIPSet
	fwd   *dns.Forwarder
	mode  *fakeMode
	run   *runnertest.Fake
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	run := runnertest.New()
	ips := newFakeIPSet()
	tracker := dns.NewTracker(ips, logger)
	tracker.Conntrack = &netfilter.Conntrack{Runner: run}
	fwd, err := dns.NewForwarder(":0", dns.ConfigUpstreams(config.DNSConfig{}), tracker, logger)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	store := shunt.NewStore(filepath.Join(t.TempDir(), "shunts.yaml"))
	mode := &fakeMode{}
	r := &Reconciler{
		Config:    config.NewLive(&cfg),
		Shunts:    store,
		IPSet:     &netfilter.IPSet{Name: "bypass", Runner: run},
		Forwarder: fwd,
		Mode:      mode,
		Logger:    logger,
	}
	return &harness{t: t, r: r, store: store, ipset: ips, fwd: fwd, mode: mode, run: run}
}

func (h *harness) create(name string, enabled bool, values ...string) {
	h.t.Helper()
	sh := shunt.Shunt{Name: name, Enabled: enabled}
	for _, v := range values {
		sh.Entries = append(sh.Entries, shunt.Entry{Value: v})
	}
	if err := h.store.Create(sh); err != nil {
		h.t.Fatal(err)
	}
}

// resolve emulates a client query answered by the forwarder: the answer is
// remembered in the resolve cache and, when the current rules match the
// query name, tracked.
func (h *harness) resolve(domain string, ips ...string) {
	h.fwd.ResolveCache().Remember(domain, ips)
	if h.fwd.Matcher().Match(domain) {
		for _, ip := range ips {
			h.fwd.TrackerRef().Track(context.Background(), domain, ip)
		}
	}
}

func (h *harness) mutate() {
	h.t.Helper()
	if err := h.r.ApplyMutation(context.Background()); err != nil {
		h.t.Fatalf("ApplyMutation: %v", err)
	}
}

func (h *harness) reconcile() {
	h.t.Helper()
	if err := h.r.Reconcile(context.Background()); err != nil {
		h.t.Fatalf("Reconcile: %v", err)
	}
}

func (h *harness) do(err error) {
	h.t.Helper()
	if err != nil {
		h.t.Fatal(err)
	}
}

// want asserts the exact kernel ipset contents.
func (h *harness) want(members ...string) {
	h.t.Helper()
	slices.Sort(members)
	if members == nil {
		members = []string{}
	}
	got := h.ipset.list()
	if got == nil {
		got = []string{}
	}
	if !slices.Equal(got, members) {
		h.t.Fatalf("ipset = %v, want %v", got, members)
	}
}

func TestMutationAddSuffixSeedsCachedSubdomains(t *testing.T) {
	h := newHarness(t)
	h.create("a", true)
	h.mutate()
	h.resolve("www.example.net", "198.51.100.1")
	h.resolve("example.net", "198.51.100.2")
	h.resolve("other.org", "198.51.100.3")
	h.want()

	h.do(h.store.AddEntry("a", "example.net"))
	h.mutate()
	h.want("198.51.100.1", "198.51.100.2")
}

func TestMutationRemoveRuleRemovesSubdomainIPs(t *testing.T) {
	for _, rule := range []string{"example.net", "domain:example.net", "keyword:example", `regexp:^www\.example\.net$`} {
		t.Run(rule, func(t *testing.T) {
			h := newHarness(t)
			h.create("a", true, rule)
			h.mutate()
			h.resolve("www.example.net", "198.51.100.1")
			h.resolve("other.org", "198.51.100.9")
			h.want("198.51.100.1")

			h.do(h.store.RemoveEntry("a", rule))
			h.mutate()
			h.want()
			if d, _ := h.fwd.TrackerRef().Count(); d != 0 {
				t.Fatalf("tracker still holds %d domains", d)
			}
		})
	}
}

func TestMutationDeleteShuntRemovesSubdomainIPs(t *testing.T) {
	h := newHarness(t)
	h.create("a", true, "example.net")
	h.mutate()
	h.resolve("www.example.net", "198.51.100.1")
	h.resolve("example.net", "198.51.100.2")
	h.want("198.51.100.1", "198.51.100.2")

	h.do(h.store.Delete("a"))
	h.mutate()
	h.want()
}

func TestMutationDomainCoveredByTwoRules(t *testing.T) {
	h := newHarness(t)
	h.create("c", true, "example.net")
	h.create("d", true, "full:www.example.net")
	h.mutate()
	h.resolve("www.example.net", "198.51.100.1")
	h.resolve("api.example.net", "198.51.100.2")
	h.want("198.51.100.1", "198.51.100.2")

	h.do(h.store.Delete("c"))
	h.mutate()
	h.want("198.51.100.1")

	h.do(h.store.Delete("d"))
	h.mutate()
	h.want()
}

func TestMutationDisableEqualsRemoval(t *testing.T) {
	h := newHarness(t)
	h.create("b", true, "example.net")
	h.mutate()
	h.resolve("www.example.net", "198.51.100.1")
	h.want("198.51.100.1")

	h.do(h.store.SetEnabled("b", false))
	h.mutate()
	h.want()

	// Re-enabling seeds from the resolve cache without a new query.
	h.do(h.store.SetEnabled("b", true))
	h.mutate()
	h.want("198.51.100.1")
}

// geoProvider is a geosite database whose content the test swaps, as a
// dlc.dat download does.
type geoProvider struct {
	mu   sync.Mutex
	cats map[string][]string
}

func (g *geoProvider) Entries(category string) ([]string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.cats[strings.ToLower(category)]
	return e, ok
}

func (g *geoProvider) set(category string, entries ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if entries == nil {
		delete(g.cats, category)
		return
	}
	g.cats[category] = entries
}

func (h *harness) geosite() *geoProvider {
	g := &geoProvider{cats: map[string][]string{}}
	h.store.SetGeositeProvider(g)
	return g
}

// A geosite shunt is a reference: a database update changes what it
// applies without touching shunts.yaml, at the next mutation. Domains the
// new data drops are swept (the tracker is keyed by query name, as for any
// rule), new ones are seeded from the resolve cache.
func TestMutationGeositeUpdateRebuildsMatcher(t *testing.T) {
	h := newHarness(t)
	g := h.geosite()
	g.set("g", "domain:a.example", "domain:b.example", "full:c.example")
	h.do(h.store.AddGeositeShunt("G", "geosite:g"))
	h.mutate()
	h.resolve("x.a.example", "198.51.100.1")
	h.resolve("x.b.example", "198.51.100.2")
	h.resolve("c.example", "198.51.100.3")
	h.resolve("d.example", "198.51.100.4")
	h.want("198.51.100.1", "198.51.100.2", "198.51.100.3")

	// The update: b and c dropped, d added.
	g.set("g", "domain:a.example", "domain:d.example")
	h.mutate()
	h.want("198.51.100.1", "198.51.100.4")
	if !h.fwd.Matcher().Match("www.d.example") || h.fwd.Matcher().Match("x.b.example") {
		t.Fatal("matcher not rebuilt from the new data")
	}

	// The category disappears from the database: the shunt stays, applies
	// nothing, its IPs leave the set.
	g.set("g")
	h.mutate()
	h.want()
	if _, err := h.store.Get("G"); err != nil {
		t.Fatal(err)
	}

	// Deleting the shunt after the category comes back removes its IPs.
	g.set("g", "domain:a.example")
	h.mutate()
	h.want("198.51.100.1")
	h.do(h.store.Delete("G"))
	h.mutate()
	h.want()
}

func TestGeositeMissingWarnedOnce(t *testing.T) {
	h := newHarness(t)
	var buf strings.Builder
	h.r.Logger = slog.New(slog.NewTextHandler(&lockedWriter{w: &buf}, nil))
	h.geosite()
	h.do(h.store.AddGeositeShunt("Z", "geosite:zz-does-not-exist"))
	h.mutate()
	h.mutate()
	if n := strings.Count(buf.String(), "geosite shunts without data"); n != 1 {
		t.Fatalf("warned %d times:\n%s", n, buf.String())
	}
}

// lockedWriter serialises writes from the logger.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestMutationStaticSharedWithDomain(t *testing.T) {
	t.Run("domain removed first", func(t *testing.T) {
		h := newHarness(t)
		h.create("e", true, "full:www.example.net")
		h.mutate()
		h.resolve("www.example.net", "198.51.100.1")
		h.do(h.store.AddEntry("e", "198.51.100.1"))
		h.mutate()
		h.want("198.51.100.1")

		h.do(h.store.RemoveEntry("e", "full:www.example.net"))
		h.mutate()
		h.want("198.51.100.1")

		h.do(h.store.RemoveEntry("e", "198.51.100.1"))
		h.mutate()
		h.want()
	})
	t.Run("static removed first", func(t *testing.T) {
		h := newHarness(t)
		h.create("e", true, "full:www.example.net", "198.51.100.1")
		h.mutate()
		h.resolve("www.example.net", "198.51.100.1")
		h.want("198.51.100.1")

		h.do(h.store.RemoveEntry("e", "198.51.100.1"))
		h.mutate()
		h.want("198.51.100.1")

		h.do(h.store.RemoveEntry("e", "full:www.example.net"))
		h.mutate()
		h.want()
	})
}

func TestMutationMixedCaseRuleValues(t *testing.T) {
	h := newHarness(t)
	// Written straight to YAML, bypassing the store's normalisation.
	h.create("m", true, "Example.NET", "full:WWW.Other.Org")
	h.mutate()
	h.resolve("www.example.net", "198.51.100.1")
	h.resolve("www.other.org", "198.51.100.2")
	h.want("198.51.100.1", "198.51.100.2")

	h.do(h.store.Delete("m"))
	h.mutate()
	h.want()
}

func TestReconcileFullSeedReseedsEverything(t *testing.T) {
	h := newHarness(t)
	h.create("a", true, "example.net")
	h.reconcile()
	h.resolve("www.example.net", "198.51.100.1")
	h.want("198.51.100.1")

	// Lose the tracker state for a still-matched domain.
	h.fwd.TrackerRef().RemoveDomain(context.Background(), "www.example.net")
	h.want()

	// A mutation only seeds newly matched domains: nothing changes.
	h.mutate()
	h.want()

	// A full reconcile re-seeds every matched cached domain.
	h.reconcile()
	h.want("198.51.100.1")
}

func TestMutationCancelledMidSweepConverges(t *testing.T) {
	h := newHarness(t)
	h.create("a", true, "one.example", "two.example")
	h.mutate()
	h.resolve("www.one.example", "198.51.100.1")
	h.resolve("www.two.example", "198.51.100.2")
	h.want("198.51.100.1", "198.51.100.2")

	h.do(h.store.Delete("a"))
	ctx, cancel := context.WithCancel(context.Background())
	h.ipset.onDel = cancel // the first del sees a cancelled context and fails
	err := h.r.ApplyMutation(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ApplyMutation error = %v, want context.Canceled", err)
	}
	h.ipset.onDel = nil

	// Whatever is still in the kernel is either still tracked or an orphan
	// the next call retries; the next call converges.
	h.mutate()
	h.want()
	if d, ips := h.fwd.TrackerRef().Count(); d != 0 || ips != 0 {
		t.Fatalf("tracker holds %d domains / %d ips", d, ips)
	}
}

func TestMutationCancelledMidSeedConverges(t *testing.T) {
	h := newHarness(t)
	h.create("a", true)
	h.mutate()
	h.resolve("www.example.net", "198.51.100.1")

	h.do(h.store.AddEntry("a", "example.net"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.r.ApplyMutation(ctx); err == nil {
		t.Fatal("ApplyMutation with a cancelled context succeeded")
	}
	h.want()

	// The rule is already in the matcher, so only the forced full seed
	// brings the cached domain in.
	h.mutate()
	h.want("198.51.100.1")
}

func TestRoutingReconcileOnlyOnFullReconcile(t *testing.T) {
	h := newHarness(t)
	h.create("a", true, "example.net")
	for i := 0; i < 3; i++ {
		h.mutate()
	}
	if h.mode.reconciles != 0 || h.mode.teardowns != 0 {
		t.Fatalf("mutation touched routing: reconciles=%d teardowns=%d", h.mode.reconciles, h.mode.teardowns)
	}
	// Every full reconcile converges the rules, also with an unchanged
	// config, and never tears them down.
	for i := 1; i <= 3; i++ {
		h.reconcile()
		if h.mode.reconciles != i {
			t.Fatalf("after %d reconciles Mode.Reconcile ran %d times", i, h.mode.reconciles)
		}
	}
	if err := h.r.SwitchProxy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.mode.reconciles != 4 || h.mode.teardowns != 0 {
		t.Fatalf("SwitchProxy: reconciles=%d teardowns=%d", h.mode.reconciles, h.mode.teardowns)
	}
}

func TestInvalidEntryWarnedOnceWithShuntName(t *testing.T) {
	h := newHarness(t)
	var buf strings.Builder
	h.r.Logger = slog.New(slog.NewTextHandler(&buf, nil))
	h.create("bad", true, "regexp:(", "ok.example", "2001:db8::1")
	h.mutate()
	h.mutate()
	out := buf.String()
	if n := strings.Count(out, "shunt entry not applied"); n != 2 {
		t.Fatalf("%d warnings, want 2 (regexp and IPv6, once each):\n%s", n, out)
	}
	if !strings.Contains(out, "shunt=bad") || !strings.Contains(out, `value=regexp:(`) {
		t.Fatalf("warning lacks shunt/value:\n%s", out)
	}
	h.resolve("www.ok.example", "198.51.100.1")
	h.want("198.51.100.1")
}

// resolveChain feeds the forwarder an upstream answer for qname that CNAMEs
// through chain to the A records ips, as handleQuery does after an upstream
// round trip.
func (h *harness) resolveChain(qname string, chain []string, ips ...string) {
	m := &mdns.Msg{MsgHeader: mdns.MsgHeader{Response: true, Rcode: mdns.RcodeSuccess}}
	owner := qname + "."
	for _, c := range chain {
		m.Answer = append(m.Answer, &mdns.CNAME{
			Hdr:   mdns.Header{Name: owner, TTL: 300, Class: mdns.ClassINET},
			CNAME: rdata.CNAME{Target: c + "."},
		})
		owner = c + "."
	}
	for _, ip := range ips {
		m.Answer = append(m.Answer, &mdns.A{
			Hdr: mdns.Header{Name: owner, TTL: 300, Class: mdns.ClassINET},
			A:   rdata.A{Addr: netip.MustParseAddr(ip)},
		})
	}
	h.fwd.RecordAnswer(context.Background(), qname, m)
}

func TestMutationCNAMETargetRuleSeedsAndSweeps(t *testing.T) {
	h := newHarness(t)
	h.create("a", true)
	h.mutate()
	h.resolveChain("www.shop.com", []string{"shop.cdn.cloudfront.net"}, "13.32.10.5", "13.32.10.6")
	h.resolve("other.org", "198.51.100.9")
	h.want()

	// A rule on the CNAME target seeds from the cache without a new query.
	h.do(h.store.AddEntry("a", "cloudfront.net"))
	h.mutate()
	h.want("13.32.10.5", "13.32.10.6")
	if got := h.fwd.TrackerRef().Domains(); !slices.Equal(got, []string{"shop.cdn.cloudfront.net"}) {
		t.Fatalf("tracker keys = %v, want the target name", got)
	}

	// An unrelated mutation does not sweep it: the key still matches.
	h.do(h.store.AddEntry("a", "unrelated.net"))
	h.mutate()
	h.want("13.32.10.5", "13.32.10.6")

	// The next answer through the forwarder keeps it under the target name.
	h.resolveChain("www.shop.com", []string{"shop.cdn.cloudfront.net"}, "13.32.10.5", "13.32.10.6")
	if got := h.fwd.TrackerRef().Domains(); !slices.Equal(got, []string{"shop.cdn.cloudfront.net"}) {
		t.Fatalf("tracker keys after a live answer = %v", got)
	}

	// Removing the rule sweeps them.
	h.do(h.store.RemoveEntry("a", "cloudfront.net"))
	h.mutate()
	h.want()

	// Re-adding the rule seeds again; a full reconcile keeps it.
	h.do(h.store.AddEntry("a", "cloudfront.net"))
	h.mutate()
	h.reconcile()
	h.want("13.32.10.5", "13.32.10.6")
	h.do(h.store.Delete("a"))
	h.mutate()
	h.want()
}

func TestMutationCNAMEQnameRuleEndToEnd(t *testing.T) {
	h := newHarness(t)
	h.create("a", true, "shop.com")
	h.mutate()
	h.resolveChain("www.shop.com", []string{"shop.cdn.cloudfront.net"}, "13.32.10.5")
	h.want("13.32.10.5")
	if got := h.fwd.TrackerRef().Domains(); !slices.Equal(got, []string{"www.shop.com"}) {
		t.Fatalf("tracker keys = %v, want the query name", got)
	}

	// A second rule on the target seeds the cached target name as well, so
	// dropping the qname rule sweeps the qname key but keeps the IP.
	h.do(h.store.AddEntry("a", "cloudfront.net"))
	h.mutate()
	h.do(h.store.RemoveEntry("a", "shop.com"))
	h.mutate()
	h.want("13.32.10.5")
	if got := h.fwd.TrackerRef().Domains(); !slices.Equal(got, []string{"shop.cdn.cloudfront.net"}) {
		t.Fatalf("tracker keys = %v, want the target name", got)
	}

	h.do(h.store.RemoveEntry("a", "cloudfront.net"))
	h.mutate()
	h.want()
}

// A routing failure (e.g. TPROXY unavailable) fails the full reconcile; the
// ipset side is still converged.
func TestReconcileRoutingErrorPropagates(t *testing.T) {
	h := newHarness(t)
	h.create("a", true, "198.51.100.7")
	h.mode.err = errors.New("udp tproxy: scripted")
	err := h.r.Reconcile(context.Background())
	if err == nil || !strings.Contains(err.Error(), "udp tproxy") {
		t.Fatalf("Reconcile error = %v", err)
	}
	h.want("198.51.100.7")
}
