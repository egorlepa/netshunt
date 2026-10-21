package routing

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/platform/runnertest"
)

// fakeNet simulates iptables (nat/mangle), `ip rule` and `ip route` well
// enough for Reconcile: rules are stored canonically and printed the way
// iptables 1.4.21 on the router prints them.
type fakeNet struct {
	mu       sync.Mutex
	chains   map[string][]string // "table/chain" -> canonical rule keys
	builtin  map[string]bool
	ipRule   bool
	ipRoute  bool
	mutating []string
	// after runs after every successful mutating iptables command.
	after func(f *fakeNet, cmd string)
	// failIf makes a mutating command whose line contains it fail.
	failIf string
}

func newFakeNet() *fakeNet {
	return &fakeNet{
		chains:  map[string][]string{"nat/PREROUTING": nil, "mangle/PREROUTING": nil, "filter/FORWARD": nil},
		builtin: map[string]bool{"nat/PREROUTING": true, "mangle/PREROUTING": true, "filter/FORWARD": true},
	}
}

var errNoChain = errors.New("iptables: No chain/target/match by that name")

// routerForm prints a canonical rule like iptables -S does.
func routerForm(key string) string {
	t := strings.Fields(key)
	var out []string
	proto := ""
	for i := 0; i < len(t); i++ {
		if t[i] == "-p" && i+1 < len(t) {
			proto = t[i+1]
		}
		if (t[i] == "--dport" || t[i] == "--sport") && proto != "" {
			out = append(out, "-m", proto)
		}
		out = append(out, t[i])
		if t[i] == "--on-port" && i+1 < len(t) {
			out = append(out, t[i+1], "--on-ip", "0.0.0.0")
			i++
		}
	}
	return strings.Join(out, " ")
}

// seed loads `iptables -S`-style lines ("-A CHAIN ...") into table.
func (f *fakeNet) seed(table string, lines ...string) {
	for _, l := range lines {
		fl := strings.Fields(l)
		if fl[0] == "-N" {
			if _, ok := f.chains[table+"/"+fl[1]]; !ok {
				f.chains[table+"/"+fl[1]] = nil
			}
			continue
		}
		k := table + "/" + fl[1]
		f.chains[k] = append(f.chains[k], canonicalRule(fl[2:]))
	}
}

func (f *fakeNet) save(table, chain string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, k := range f.chains[table+"/"+chain] {
		out = append(out, "-A "+chain+" "+routerForm(k))
	}
	return out
}

func (f *fakeNet) handle(name string, args []string) (string, error, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := name + " " + strings.Join(args, " ")
	switch name {
	case "iptables":
		return f.iptables(line, args)
	case "ip":
		switch strings.Join(args[:2], " ") {
		case "rule show":
			out := "0:\tfrom all lookup local\n32766:\tfrom all lookup main"
			if f.ipRule {
				out += "\n32000:\tfrom all fwmark 0x1 lookup 100 "
			}
			return out, nil, true
		case "rule add":
			f.mutating = append(f.mutating, line)
			f.ipRule = true
			return "", nil, true
		case "rule del":
			f.mutating = append(f.mutating, line)
			f.ipRule = false
			return "", nil, true
		case "route show":
			if f.ipRoute {
				return "local default dev lo  scope host", nil, true
			}
			return "", nil, true
		case "route replace":
			f.mutating = append(f.mutating, line)
			f.ipRoute = true
			return "", nil, true
		case "route del":
			f.mutating = append(f.mutating, line)
			f.ipRoute = false
			return "", nil, true
		}
	case "modprobe", "insmod":
		f.mutating = append(f.mutating, line)
		return "", nil, true
	}
	return "", nil, false
}

func (f *fakeNet) iptables(line string, args []string) (string, error, bool) {
	if args[0] == "-w" {
		args = args[1:]
	}
	if args[0] != "-t" {
		return "", errors.New("table required"), true
	}
	table, op, chain := args[1], args[2], args[3]
	rest := args[4:]
	k := table + "/" + chain
	rules, exists := f.chains[k]

	if op == "-S" {
		if !exists {
			return "", errNoChain, true
		}
		var out []string
		if f.builtin[k] {
			out = append(out, "-P "+chain+" ACCEPT")
		} else {
			out = append(out, "-N "+chain)
		}
		for _, r := range rules {
			out = append(out, "-A "+chain+" "+routerForm(r))
		}
		return strings.Join(out, "\n"), nil, true
	}
	if op == "-C" {
		if exists && slices.Contains(rules, canonicalRule(rest)) {
			return "", nil, true
		}
		return "", errors.New("no rule"), true
	}

	f.mutating = append(f.mutating, line)
	if f.failIf != "" && strings.Contains(line, f.failIf) {
		return "", errors.New("scripted failure"), true
	}
	num := func() (int, []string, bool) {
		if len(rest) > 0 {
			if n, err := strconv.Atoi(rest[0]); err == nil {
				return n, rest[1:], true
			}
		}
		return 0, rest, false
	}
	switch op {
	case "-N":
		if exists {
			return "", errors.New("chain exists"), true
		}
		f.chains[k] = nil
	case "-X":
		if !exists {
			return "", errNoChain, true
		}
		delete(f.chains, k)
	case "-F":
		f.chains[k] = nil
	case "-A":
		if !exists {
			return "", errNoChain, true
		}
		f.chains[k] = append(rules, canonicalRule(rest))
	case "-I":
		n, spec, ok := num()
		if !ok {
			n = 1
		}
		if !exists || n < 1 || n > len(rules)+1 {
			return "", fmt.Errorf("bad -I %d", n), true
		}
		f.chains[k] = slices.Insert(slices.Clone(rules), n-1, canonicalRule(spec))
	case "-R":
		n, spec, _ := num()
		if n < 1 || n > len(rules) {
			return "", fmt.Errorf("bad -R %d", n), true
		}
		rules[n-1] = canonicalRule(spec)
	case "-D":
		n, spec, ok := num()
		if ok {
			if n < 1 || n > len(rules) {
				return "", fmt.Errorf("bad -D %d", n), true
			}
			f.chains[k] = slices.Delete(slices.Clone(rules), n-1, n)
		} else {
			i := slices.Index(rules, canonicalRule(spec))
			if i < 0 {
				return "", errors.New("no such rule"), true
			}
			f.chains[k] = slices.Delete(slices.Clone(rules), i, i+1)
		}
	default:
		return "", fmt.Errorf("unsupported op %s", op), true
	}
	if f.after != nil {
		f.after(f, line)
	}
	return "", nil, true
}

func (f *fakeNet) takeMutating() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.mutating
	f.mutating = nil
	return m
}

type testEnv struct {
	net  *fakeNet
	cfg  *config.Config
	live *config.Live
	r    *Redirect
	run  *runnertest.Fake
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	cfg := config.Defaults()
	cfg.Routing.LocalPort = 1081
	cfg.Network.EntwareInterface = "br0"
	cfg.Network.AdditionalInterfaces = []string{"awg0"}
	live := config.NewLive(&cfg)
	fn := newFakeNet()
	run := runnertest.New()
	run.Handler = fn.handle
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &testEnv{net: fn, cfg: &cfg, live: live, r: newRedirect(live, logger, run, ""), run: run}
}

func (e *testEnv) setConfig(mod func(c *config.Config)) {
	c := *e.cfg
	c.Network.AdditionalInterfaces = slices.Clone(c.Network.AdditionalInterfaces)
	c.ExcludedNetworks = slices.Clone(c.ExcludedNetworks)
	mod(&c)
	e.cfg = &c
	e.live.Store(&c)
}

func (e *testEnv) reconcile(t *testing.T) []string {
	t.Helper()
	if err := e.r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return e.net.takeMutating()
}

// The exact state on the owner's router (1.5.7~rc15), including foreign
// rules from NDM and AmneziaWG.
var routerNat = []string{
	"-A PREROUTING -d 10.7.1.0/24 -i awg0 -j NETMAP --to 192.168.1.0/24",
	"-A PREROUTING -j _NDM_DNAT",
	"-A PREROUTING -j _NDM_DNS_REDIRECT",
	"-A PREROUTING -m ndmmark --ndmmark 0x0/0x8 -j _NDM_UPNP_REDIRECT_SYS",
	"-A PREROUTING -i br0 -j NSHUNT",
	"-A PREROUTING -i awg0 -j NSHUNT",
	"-A PREROUTING -i br0 -p udp -m udp --dport 53 -j REDIRECT --to-ports 53",
	"-A PREROUTING -i br0 -p tcp -m tcp --dport 53 -j REDIRECT --to-ports 53",
	"-A PREROUTING -i awg0 -p udp -m udp --dport 53 -j REDIRECT --to-ports 53",
	"-A PREROUTING -i awg0 -p tcp -m tcp --dport 53 -j REDIRECT --to-ports 53",
	"-N NSHUNT",
	"-A NSHUNT -d 10.0.0.0/8 -j RETURN",
	"-A NSHUNT -d 172.16.0.0/12 -j RETURN",
	"-A NSHUNT -d 192.168.0.0/16 -j RETURN",
	"-A NSHUNT -p tcp -m set --match-set bypass dst -j REDIRECT --to-ports 1081",
}

var routerMangle = []string{
	"-A PREROUTING -d 224.0.0.0/4 -j _NDM_PREROUTING_MC",
	"-A PREROUTING -j _NDM_IPSEC_PREROUTING",
	"-A PREROUTING -j _NDM_VPN_PREROUTING",
	"-A PREROUTING -j _NDM_PREROUTING_TTL",
	"-A PREROUTING -j _NDM_HOTSPOT_PREROUTING_MANGL",
	"-A PREROUTING -m mark --mark 0x0 -j _NDM_DNSRT_PREROUTING_MANGLE",
	"-A PREROUTING -i br0 -j NSHUNT_UDP",
	"-A PREROUTING -i awg0 -j NSHUNT_UDP",
	"-N NSHUNT_UDP",
	"-A NSHUNT_UDP -d 10.0.0.0/8 -j RETURN",
	"-A NSHUNT_UDP -d 172.16.0.0/12 -j RETURN",
	"-A NSHUNT_UDP -d 192.168.0.0/16 -j RETURN",
	"-A NSHUNT_UDP -p udp -m set --match-set bypass dst -j TPROXY --on-port 1081 --on-ip 0.0.0.0 --tproxy-mark 0x1/0x1",
}

// routerFilter is the filter table with the kill switch in place: our jump
// first, then the AmneziaWG ACCEPTs and NDM's chains.
var routerFilter = []string{
	"-A FORWARD -j NSHUNT_KS",
	"-A FORWARD -o awg0 -j ACCEPT",
	"-A FORWARD -i awg0 -j ACCEPT",
	"-A FORWARD -j _NDM_SL_FORWARD",
	"-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
	"-A FORWARD -j _NDM_FORWARD",
	"-N NSHUNT_KS",
	"-A NSHUNT_KS -d 10.0.0.0/8 -j RETURN",
	"-A NSHUNT_KS -d 172.16.0.0/12 -j RETURN",
	"-A NSHUNT_KS -d 192.168.0.0/16 -j RETURN",
	"-A NSHUNT_KS -m set --match-set bypass dst -j DROP",
}

func routerEnv(t *testing.T) *testEnv {
	e := newEnv(t)
	e.net.seed("nat", routerNat...)
	e.net.seed("mangle", routerMangle...)
	e.net.seed("filter", routerFilter...)
	e.net.ipRule, e.net.ipRoute = true, true
	return e
}

func foreign(lines []string) []string {
	var out []string
	for _, l := range lines {
		if isForeignLine(l) {
			out = append(out, routerForm(canonicalRule(strings.Fields(l)[2:])))
		}
	}
	return out
}

// isForeignLine reports whether an `iptables -S` line is a PREROUTING or
// FORWARD rule netshunt does not own.
func isForeignLine(l string) bool {
	return (strings.HasPrefix(l, "-A PREROUTING") || strings.HasPrefix(l, "-A FORWARD")) &&
		!strings.Contains(l, "NSHUNT") && !strings.Contains(l, "--dport 53")
}

func assertForeignKept(t *testing.T, e *testEnv) {
	t.Helper()
	for _, c := range []struct {
		table, chain string
		lines        []string
	}{{"nat", "PREROUTING", routerNat}, {"mangle", "PREROUTING", routerMangle}, {"filter", "FORWARD", routerFilter}} {
		got := e.net.save(c.table, c.chain)
		for _, f := range foreign(linesOf(c.lines, c.chain)) {
			if !slices.Contains(got, "-A "+c.chain+" "+f) {
				t.Errorf("%s: foreign rule %q gone; %s = %v", c.table, f, c.chain, got)
			}
		}
	}
}

func TestParserAcceptsRouterForms(t *testing.T) {
	cases := []struct {
		printed string
		given   []string
	}{
		{"-d 10.0.0.0/8 -j RETURN", []string{"-d", "10.0.0.0/8", "-j", "RETURN"}},
		{"-p tcp -m set --match-set bypass dst -j REDIRECT --to-ports 1081",
			[]string{"-p", "tcp", "-m", "set", "--match-set", "bypass", "dst", "-j", "REDIRECT", "--to-port", "1081"}},
		{"-p udp -m set --match-set bypass dst -j TPROXY --on-port 1081 --on-ip 0.0.0.0 --tproxy-mark 0x1/0x1",
			[]string{"-p", "udp", "-m", "set", "--match-set", "bypass", "dst", "-j", "TPROXY", "--on-port", "1081", "--tproxy-mark", "0x1/0x1"}},
		{"-i br0 -j NSHUNT", []string{"-i", "br0", "-j", "NSHUNT"}},
		{"-i br0 -p udp -m udp --dport 53 -j REDIRECT --to-ports 53", DNSRedirectRule("br0", "udp")[1:]},
		{"-i br0 -p tcp -m tcp --dport 53 -j REDIRECT --to-ports 53", DNSRedirectRule("br0", "tcp")[1:]},
		// Long options, option order, dotted masks, host addresses.
		{"-d 10.0.0.0/8 -j RETURN", []string{"--destination", "10.1.2.3/255.0.0.0", "--jump", "RETURN"}},
		{"-d 1.2.3.4/32 -i br0 -j RETURN", []string{"-i", "br0", "-d", "1.2.3.4", "-j", "RETURN"}},
		{"-p udp -j TPROXY --on-port 1 --tproxy-mark 0x1/0xffffffff", []string{"-p", "udp", "-j", "TPROXY", "--on-port", "1", "--tproxy-mark", "0x1"}},
	}
	for _, c := range cases {
		got, want := canonicalRule(strings.Fields(c.printed)), canonicalRule(c.given)
		if got != want {
			t.Errorf("printed %q -> %q, given %v -> %q", c.printed, got, c.given, want)
		}
	}
	// Different rules stay different.
	if canonicalRule(strings.Fields("-i br0 -j NSHUNT")) == canonicalRule(strings.Fields("-i awg0 -j NSHUNT")) {
		t.Error("interfaces collapsed")
	}
	if canonicalRule(strings.Fields("! -i br0 -j NSHUNT")) == canonicalRule(strings.Fields("-i br0 -j NSHUNT")) {
		t.Error("negation lost")
	}
	if canonicalRule(strings.Fields("-p udp -m udp --dport 53 -j RETURN")) == canonicalRule(strings.Fields("-p udp -m udp --dport 5353 -j RETURN")) {
		t.Error("ports collapsed")
	}
	rules := parseSave(strings.Join(routerNat, "\n"), "NSHUNT")
	if len(rules) != 4 || rules[3].key != canonicalRule(strings.Fields("-p tcp -m set --match-set bypass dst -j REDIRECT --to-ports 1081")) {
		t.Errorf("parseSave NSHUNT = %+v", rules)
	}
}

func TestReconcileUnchangedRunsNoMutations(t *testing.T) {
	e := routerEnv(t)
	if m := e.reconcile(t); len(m) != 0 {
		t.Fatalf("mutating commands on an unchanged router: %v", m)
	}
	for _, c := range e.run.Calls() {
		if !strings.Contains(c, " -S ") && !strings.HasPrefix(c, "ip rule show") && !strings.HasPrefix(c, "ip route show") {
			t.Errorf("non-read command: %q", c)
		}
	}
	if n := len(e.run.Calls()); n != 8 {
		t.Errorf("%d commands, want 8 reads: %v", n, e.run.Calls())
	}
}

func TestReconcileFromEmptyBuildsAllInOrder(t *testing.T) {
	e := newEnv(t)
	e.net.seed("nat", foreignOnly(routerNat)...)
	e.net.seed("mangle", foreignOnly(routerMangle)...)
	e.net.seed("filter", foreignOnly(routerFilter)...)

	m := e.reconcile(t)
	if len(m) == 0 {
		t.Fatal("nothing created")
	}
	for _, c := range m {
		if strings.Contains(c, " -F ") || strings.Contains(c, " -X ") {
			t.Errorf("flush/delete chain on build: %q", c)
		}
	}
	if got, want := e.net.save("nat", "NSHUNT"), ourLines(routerNat, "NSHUNT"); !slices.Equal(got, want) {
		t.Errorf("NSHUNT = %v\nwant %v", got, want)
	}
	if got, want := e.net.save("mangle", "NSHUNT_UDP"), ourLines(routerMangle, "NSHUNT_UDP"); !slices.Equal(got, want) {
		t.Errorf("NSHUNT_UDP = %v\nwant %v", got, want)
	}
	if got, want := e.net.save("nat", "PREROUTING"), linesOf(routerNat, "PREROUTING"); !slices.Equal(got, want) {
		t.Errorf("nat PREROUTING = %v\nwant %v", got, want)
	}
	if got, want := e.net.save("mangle", "PREROUTING"), linesOf(routerMangle, "PREROUTING"); !slices.Equal(got, want) {
		t.Errorf("mangle PREROUTING = %v\nwant %v", got, want)
	}
	if got, want := e.net.save("filter", "NSHUNT_KS"), linesOf(routerFilter, "NSHUNT_KS"); !slices.Equal(got, want) {
		t.Errorf("NSHUNT_KS = %v\nwant %v", got, want)
	}
	if got, want := e.net.save("filter", "FORWARD"), linesOf(routerFilter, "FORWARD"); !slices.Equal(got, want) {
		t.Errorf("FORWARD = %v\nwant %v", got, want)
	}
	if !e.net.ipRule || !e.net.ipRoute {
		t.Error("policy rule/route missing")
	}
	if n := countPrefix(m, "ip rule add"); n != 1 {
		t.Errorf("ip rule add ran %d times", n)
	}
	if m := e.reconcile(t); len(m) != 0 {
		t.Fatalf("second run mutated: %v", m)
	}
}

func TestReconcileMissingChainCreatedAndFilledInOrder(t *testing.T) {
	e := routerEnv(t)
	delete(e.net.chains, "nat/NSHUNT")
	m := e.reconcile(t)
	want := []string{"iptables -w -t nat -N NSHUNT",
		"iptables -w -t nat -I NSHUNT 1 -d 10.0.0.0/8 -j RETURN",
		"iptables -w -t nat -I NSHUNT 2 -d 172.16.0.0/12 -j RETURN",
		"iptables -w -t nat -I NSHUNT 3 -d 192.168.0.0/16 -j RETURN",
		"iptables -w -t nat -I NSHUNT 4 -p tcp -m set --match-set bypass dst -j REDIRECT --to-ports 1081",
	}
	if !slices.Equal(m, want) {
		t.Fatalf("commands = %v\nwant %v", m, want)
	}
	if got := e.net.save("nat", "NSHUNT"); !slices.Equal(got, ourLines(routerNat, "NSHUNT")) {
		t.Fatalf("NSHUNT = %v", got)
	}
}

func TestReconcilePortChangeKeepsExactlyOneRedirect(t *testing.T) {
	e := routerEnv(t)
	var bad []string
	e.net.after = func(f *fakeNet, cmd string) {
		for _, c := range []struct{ key, target string }{{"nat/NSHUNT", "REDIRECT"}, {"mangle/NSHUNT_UDP", "TPROXY"}} {
			n := 0
			for _, r := range f.chains[c.key] {
				if strings.Contains(r, "-j "+c.target) {
					n++
				}
			}
			if n != 1 {
				bad = append(bad, fmt.Sprintf("%s has %d %s rules after %q", c.key, n, c.target, cmd))
			}
		}
	}
	e.setConfig(func(c *config.Config) { c.Routing.LocalPort = 1082 })
	m := e.reconcile(t)
	want := []string{
		"iptables -w -t nat -R NSHUNT 4 -p tcp -m set --match-set bypass dst -j REDIRECT --to-ports 1082",
		"iptables -w -t mangle -R NSHUNT_UDP 4 -p udp -m set --match-set bypass dst -j TPROXY --on-port 1082 --tproxy-mark 0x1/0x1",
	}
	if !slices.Equal(m, want) {
		t.Fatalf("commands = %v\nwant %v", m, want)
	}
	if len(bad) > 0 {
		t.Fatal(strings.Join(bad, "\n"))
	}
	if got := e.net.save("nat", "NSHUNT"); got[3] != "-A NSHUNT -p tcp -m set --match-set bypass dst -j REDIRECT --to-ports 1082" {
		t.Fatalf("NSHUNT = %v", got)
	}
	if m := e.reconcile(t); len(m) != 0 {
		t.Fatalf("second run mutated: %v", m)
	}
	e.setConfig(func(c *config.Config) { c.Routing.LocalPort = 1081 })
	e.reconcile(t)
	if len(bad) > 0 {
		t.Fatal(strings.Join(bad, "\n"))
	}
	assertForeignKept(t, e)
}

func TestReconcileExcludedNetworkChanges(t *testing.T) {
	e := routerEnv(t)
	e.setConfig(func(c *config.Config) { c.ExcludedNetworks = []string{"10.0.0.0/8", "192.168.0.0/16"} })
	m := e.reconcile(t)
	want := []string{"iptables -w -t nat -D NSHUNT 2", "iptables -w -t filter -D NSHUNT_KS 2", "iptables -w -t mangle -D NSHUNT_UDP 2"}
	if !slices.Equal(m, want) {
		t.Fatalf("remove: commands = %v\nwant %v", m, want)
	}
	e.setConfig(func(c *config.Config) {
		c.ExcludedNetworks = []string{"10.0.0.0/8", "100.64.0.0/10", "192.168.0.0/16"}
	})
	m = e.reconcile(t)
	want = []string{
		"iptables -w -t nat -I NSHUNT 2 -d 100.64.0.0/10 -j RETURN",
		"iptables -w -t filter -I NSHUNT_KS 2 -d 100.64.0.0/10 -j RETURN",
		"iptables -w -t mangle -I NSHUNT_UDP 2 -d 100.64.0.0/10 -j RETURN",
	}
	if !slices.Equal(m, want) {
		t.Fatalf("add: commands = %v\nwant %v", m, want)
	}
	wantKS := []string{
		"-A NSHUNT_KS -d 10.0.0.0/8 -j RETURN",
		"-A NSHUNT_KS -d 100.64.0.0/10 -j RETURN",
		"-A NSHUNT_KS -d 192.168.0.0/16 -j RETURN",
		"-A NSHUNT_KS -m set --match-set bypass dst -j DROP",
	}
	if got := e.net.save("filter", "NSHUNT_KS"); !slices.Equal(got, wantKS) {
		t.Fatalf("NSHUNT_KS = %v\nwant %v", got, wantKS)
	}
}

func TestReconcileAddInterfaceAddsOnlyItsRules(t *testing.T) {
	e := routerEnv(t)
	e.setConfig(func(c *config.Config) { c.Network.AdditionalInterfaces = []string{"awg0", "wg1"} })
	m := e.reconcile(t)
	want := []string{
		"iptables -w -t nat -A PREROUTING -i wg1 -j NSHUNT",
		"iptables -w -t nat -A PREROUTING -i wg1 -p udp --dport 53 -j REDIRECT --to-ports 53",
		"iptables -w -t nat -A PREROUTING -i wg1 -p tcp --dport 53 -j REDIRECT --to-ports 53",
		"iptables -w -t mangle -A PREROUTING -i wg1 -j NSHUNT_UDP",
	}
	if !slices.Equal(m, want) {
		t.Fatalf("commands = %v\nwant %v", m, want)
	}
	assertForeignKept(t, e)
}

func TestReconcileRemoveInterfaceDeletesOnlyItsRules(t *testing.T) {
	e := routerEnv(t)
	e.setConfig(func(c *config.Config) { c.Network.AdditionalInterfaces = nil })
	m := e.reconcile(t)
	want := []string{
		"iptables -w -t nat -D PREROUTING -i awg0 -j NSHUNT",
		"iptables -w -t nat -D PREROUTING -i awg0 -p udp -m udp --dport 53 -j REDIRECT --to-ports 53",
		"iptables -w -t nat -D PREROUTING -i awg0 -p tcp -m tcp --dport 53 -j REDIRECT --to-ports 53",
		"iptables -w -t mangle -D PREROUTING -i awg0 -j NSHUNT_UDP",
	}
	if !slices.Equal(m, want) {
		t.Fatalf("commands = %v\nwant %v", m, want)
	}
	assertForeignKept(t, e)
	// The AmneziaWG NETMAP on awg0 is not ours and stays.
	if !slices.Contains(e.net.save("nat", "PREROUTING"), "-A PREROUTING -d 10.7.1.0/24 -i awg0 -j NETMAP --to 192.168.1.0/24") {
		t.Fatal("NETMAP removed")
	}
}

func TestReconcileEmptyInterfaceListUsesUnconditionalJump(t *testing.T) {
	e := routerEnv(t)
	e.setConfig(func(c *config.Config) {
		c.Network.EntwareInterface = ""
		c.Network.AdditionalInterfaces = nil
	})
	m := e.reconcile(t)
	// Per table, adds come before deletes, so there is no moment without a
	// jump.
	for _, table := range []string{"nat", "mangle"} {
		firstDel, lastAdd := len(m), -1
		for i, c := range m {
			if !strings.Contains(c, " -t "+table+" ") {
				continue
			}
			if strings.Contains(c, " -D PREROUTING") && i < firstDel {
				firstDel = i
			}
			if strings.Contains(c, " -A PREROUTING") {
				lastAdd = i
			}
		}
		if lastAdd < 0 || firstDel < lastAdd {
			t.Errorf("%s: delete before add: %v", table, m)
		}
	}
	nat := e.net.save("nat", "PREROUTING")
	if !slices.Contains(nat, "-A PREROUTING -j NSHUNT") {
		t.Errorf("no unconditional nat jump: %v", nat)
	}
	if !slices.Contains(e.net.save("mangle", "PREROUTING"), "-A PREROUTING -j NSHUNT_UDP") {
		t.Error("no unconditional mangle jump")
	}
	for _, l := range nat {
		if strings.Contains(l, "-i br0 -j NSHUNT") || strings.Contains(l, "-i awg0 -j NSHUNT") || strings.Contains(l, "-i awg0 -p") {
			t.Errorf("stale rule kept: %q", l)
		}
	}
	// DNS interception falls back to br0.
	if !slices.Contains(nat, "-A PREROUTING -i br0 -p udp -m udp --dport 53 -j REDIRECT --to-ports 53") {
		t.Error("br0 DNS redirect missing")
	}
	assertForeignKept(t, e)
	if m := e.reconcile(t); len(m) != 0 {
		t.Fatalf("second run mutated: %v", m)
	}
}

func TestReconcileNeverDeletesForeignRules(t *testing.T) {
	e := routerEnv(t)
	lookalikes := []string{
		"-A PREROUTING -i br0 -p udp -m udp --dport 5353 -j REDIRECT --to-ports 5353",
		"-A PREROUTING -i br0 -p udp -m udp --dport 53 -j REDIRECT --to-ports 5300",
		"-A PREROUTING -i br0 -j NSHUNT_OTHER",
		"-A PREROUTING -i br0 -p udp -m udp --dport 53 -j DNAT --to-destination 192.168.1.1",
	}
	e.net.seed("nat", lookalikes...)
	e.setConfig(func(c *config.Config) { c.Network.AdditionalInterfaces = nil; c.Routing.LocalPort = 1090 })
	e.reconcile(t)
	got := e.net.save("nat", "PREROUTING")
	for _, l := range lookalikes {
		if !slices.Contains(got, l) {
			t.Errorf("foreign rule deleted: %q", l)
		}
	}
	assertForeignKept(t, e)
}

func TestReconcileDuplicatesRemoved(t *testing.T) {
	e := routerEnv(t)
	e.net.seed("nat", "-A PREROUTING -i br0 -j NSHUNT", "-A NSHUNT -p tcp -m set --match-set bypass dst -j REDIRECT --to-ports 1081")
	m := e.reconcile(t)
	want := []string{"iptables -w -t nat -D NSHUNT 5", "iptables -w -t nat -D PREROUTING -i br0 -j NSHUNT"}
	if !slices.Equal(m, want) {
		t.Fatalf("commands = %v\nwant %v", m, want)
	}
	if !slices.Contains(e.net.save("nat", "PREROUTING"), "-A PREROUTING -i br0 -j NSHUNT") {
		t.Fatal("both copies deleted")
	}
}

func TestReconcilePolicyRoute(t *testing.T) {
	e := routerEnv(t)
	e.net.ipRule, e.net.ipRoute = false, false
	m := e.reconcile(t)
	want := []string{"ip rule add pref 32000 fwmark 0x1 table 100", "ip route replace local 0/0 dev lo table 100"}
	if !slices.Equal(m, want) {
		t.Fatalf("commands = %v\nwant %v", m, want)
	}
	if m := e.reconcile(t); len(m) != 0 {
		t.Fatalf("present: mutated %v", m)
	}
}

// TPROXY is mandatory: a failure to install it fails Reconcile, but only
// after the TCP rules are converged, so a partial setup is as good as it
// can be.
func TestReconcileTproxyFailureIsErrorAfterTCPConverged(t *testing.T) {
	e := newEnv(t)
	e.net.seed("nat", foreignOnly(routerNat)...)
	e.net.seed("mangle", foreignOnly(routerMangle)...)
	e.net.seed("filter", foreignOnly(routerFilter)...)
	e.net.failIf = "-j TPROXY"
	err := e.r.Reconcile(context.Background())
	if err == nil || !strings.Contains(err.Error(), "tproxy") {
		t.Fatalf("Reconcile error = %v, want a tproxy error", err)
	}
	m := e.net.takeMutating()
	if got, want := e.net.save("nat", "NSHUNT"), ourLines(routerNat, "NSHUNT"); !slices.Equal(got, want) {
		t.Fatalf("NSHUNT = %v\nwant %v", got, want)
	}
	if got, want := e.net.save("nat", "PREROUTING"), linesOf(routerNat, "PREROUTING"); !slices.Equal(got, want) {
		t.Errorf("nat PREROUTING = %v\nwant %v", got, want)
	}
	// The kill switch is in place, so UDP to shunted addresses is dropped,
	// not sent direct, while TPROXY is missing.
	if got, want := e.net.save("filter", "NSHUNT_KS"), linesOf(routerFilter, "NSHUNT_KS"); !slices.Equal(got, want) {
		t.Errorf("NSHUNT_KS = %v\nwant %v", got, want)
	}
	if got, want := e.net.save("filter", "FORWARD"), linesOf(routerFilter, "FORWARD"); !slices.Equal(got, want) {
		t.Errorf("FORWARD = %v\nwant %v", got, want)
	}
	for _, l := range e.net.save("mangle", "PREROUTING") {
		if strings.Contains(l, "NSHUNT_UDP") {
			t.Errorf("mangle jump added without TPROXY: %q", l)
		}
	}
	if countPrefix(m, "modprobe") != 1 {
		t.Errorf("module load attempts: %v", m)
	}

	// Once TPROXY works, the next run completes the UDP side.
	e.net.failIf = ""
	e.reconcile(t)
	if got, want := e.net.save("mangle", "NSHUNT_UDP"), ourLines(routerMangle, "NSHUNT_UDP"); !slices.Equal(got, want) {
		t.Fatalf("NSHUNT_UDP = %v\nwant %v", got, want)
	}
	if !e.net.ipRule || !e.net.ipRoute {
		t.Error("policy rule/route missing")
	}
}

func TestTeardownRemovesOnlyOurs(t *testing.T) {
	e := routerEnv(t)
	if err := e.r.TeardownRules(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.net.chains["nat/NSHUNT"]; ok {
		t.Error("NSHUNT left")
	}
	if _, ok := e.net.chains["mangle/NSHUNT_UDP"]; ok {
		t.Error("NSHUNT_UDP left")
	}
	if _, ok := e.net.chains["filter/NSHUNT_KS"]; ok {
		t.Error("NSHUNT_KS left")
	}
	if got, want := e.net.save("filter", "FORWARD"), foreignPrefixed(linesOf(routerFilter, "FORWARD")); !slices.Equal(got, want) {
		t.Errorf("FORWARD = %v\nwant %v", got, want)
	}
	if got, want := e.net.save("nat", "PREROUTING"), foreignPrefixed(linesOf(routerNat, "PREROUTING")); !slices.Equal(got, want) {
		t.Errorf("nat PREROUTING = %v\nwant %v", got, want)
	}
	if got, want := e.net.save("mangle", "PREROUTING"), foreignPrefixed(linesOf(routerMangle, "PREROUTING")); !slices.Equal(got, want) {
		t.Errorf("mangle PREROUTING = %v\nwant %v", got, want)
	}
	if e.net.ipRule || e.net.ipRoute {
		t.Error("policy route left")
	}
}

func foreignOnly(lines []string) []string {
	var out []string
	for _, l := range lines {
		if isForeignLine(l) {
			out = append(out, l)
		}
	}
	return out
}

// foreignPrefixed returns the foreign rules of lines (all of one chain) as
// `iptables -S` prints them.
func foreignPrefixed(lines []string) []string {
	var out []string
	for _, l := range lines {
		if isForeignLine(l) {
			out = append(out, strings.Join(strings.Fields(l)[:2], " ")+" "+routerForm(canonicalRule(strings.Fields(l)[2:])))
		}
	}
	return out
}

func linesOf(lines []string, chain string) []string {
	var out []string
	for _, l := range lines {
		if strings.HasPrefix(l, "-A "+chain+" ") {
			out = append(out, l)
		}
	}
	return out
}

func ourLines(lines []string, chain string) []string { return linesOf(lines, chain) }

func countPrefix(cmds []string, p string) int {
	n := 0
	for _, c := range cmds {
		if strings.HasPrefix(c, p) {
			n++
		}
	}
	return n
}

func TestKillSwitchFromEmpty(t *testing.T) {
	e := routerEnv(t)
	delete(e.net.chains, "filter/NSHUNT_KS")
	e.net.chains["filter/FORWARD"] = nil
	e.net.seed("filter", foreignOnly(routerFilter)...)
	m := e.reconcile(t)
	want := []string{
		"iptables -w -t filter -N NSHUNT_KS",
		"iptables -w -t filter -I NSHUNT_KS 1 -d 10.0.0.0/8 -j RETURN",
		"iptables -w -t filter -I NSHUNT_KS 2 -d 172.16.0.0/12 -j RETURN",
		"iptables -w -t filter -I NSHUNT_KS 3 -d 192.168.0.0/16 -j RETURN",
		"iptables -w -t filter -I NSHUNT_KS 4 -m set --match-set bypass dst -j DROP",
		"iptables -w -t filter -I FORWARD 1 -j NSHUNT_KS",
	}
	if !slices.Equal(m, want) {
		t.Fatalf("commands = %v\nwant %v", m, want)
	}
	if got, want := e.net.save("filter", "FORWARD"), linesOf(routerFilter, "FORWARD"); !slices.Equal(got, want) {
		t.Fatalf("FORWARD = %v\nwant %v", got, want)
	}
	if got, want := e.net.save("filter", "NSHUNT_KS"), linesOf(routerFilter, "NSHUNT_KS"); !slices.Equal(got, want) {
		t.Fatalf("NSHUNT_KS = %v\nwant %v", got, want)
	}
	assertForeignKept(t, e)
	if m := e.reconcile(t); len(m) != 0 {
		t.Fatalf("second run mutated: %v", m)
	}
}

// NDM inserted its own rules above the jump: the jump moves back to 1, and
// at no point is FORWARD without a jump.
func TestKillSwitchJumpMovedBackToFirst(t *testing.T) {
	e := routerEnv(t)
	e.net.chains["filter/FORWARD"] = nil
	e.net.seed("filter",
		"-A FORWARD -j _NDM_SL_FORWARD",
		"-A FORWARD -o awg0 -j ACCEPT",
		"-A FORWARD -j NSHUNT_KS",
		"-A FORWARD -i awg0 -j ACCEPT",
		"-A FORWARD -j NSHUNT_KS",
	)
	var bad []string
	e.net.after = func(f *fakeNet, cmd string) {
		if !slices.Contains(f.chains["filter/FORWARD"], "-j NSHUNT_KS") {
			bad = append(bad, "no jump after "+cmd)
		}
	}
	m := e.reconcile(t)
	want := []string{
		"iptables -w -t filter -I FORWARD 1 -j NSHUNT_KS",
		"iptables -w -t filter -D FORWARD 6",
		"iptables -w -t filter -D FORWARD 4",
	}
	if !slices.Equal(m, want) {
		t.Fatalf("commands = %v\nwant %v", m, want)
	}
	if len(bad) > 0 {
		t.Fatal(strings.Join(bad, "\n"))
	}
	wantFwd := []string{
		"-A FORWARD -j NSHUNT_KS",
		"-A FORWARD -j _NDM_SL_FORWARD",
		"-A FORWARD -o awg0 -j ACCEPT",
		"-A FORWARD -i awg0 -j ACCEPT",
	}
	if got := e.net.save("filter", "FORWARD"); !slices.Equal(got, wantFwd) {
		t.Fatalf("FORWARD = %v\nwant %v", got, wantFwd)
	}
	if m := e.reconcile(t); len(m) != 0 {
		t.Fatalf("second run mutated: %v", m)
	}
}

// A duplicate jump below the first one is removed; the first stays.
func TestKillSwitchDuplicateJumpRemoved(t *testing.T) {
	e := routerEnv(t)
	e.net.seed("filter", "-A FORWARD -j NSHUNT_KS")
	m := e.reconcile(t)
	if want := []string{"iptables -w -t filter -D FORWARD 7"}; !slices.Equal(m, want) {
		t.Fatalf("commands = %v\nwant %v", m, want)
	}
	if got, want := e.net.save("filter", "FORWARD"), linesOf(routerFilter, "FORWARD"); !slices.Equal(got, want) {
		t.Fatalf("FORWARD = %v\nwant %v", got, want)
	}
}

func TestKillSwitchStaleRuleInChainReplaced(t *testing.T) {
	e := routerEnv(t)
	e.setConfig(func(c *config.Config) { c.IPSet.TableName = "bypass2" })
	m := e.reconcile(t)
	if !slices.Contains(m, "iptables -w -t filter -R NSHUNT_KS 4 -m set --match-set bypass2 dst -j DROP") {
		t.Fatalf("DROP rule not replaced in place: %v", m)
	}
}
