package routing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"syscall"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/platform"
)

const (
	redirectChainName    = "NSHUNT"
	redirectUDPChainName = "NSHUNT_UDP"
	// KillSwitchChain is the filter-table chain FORWARD jumps to first; see
	// desired() for what it drops and why.
	KillSwitchChain = "NSHUNT_KS"
	fwmark          = "0x1"
	routeTable      = "100"
	// rulePref is the policy-rule priority. It must stay clear of the
	// priorities Keenetic NDM manages itself (it owns 100/101 among others
	// and deletes by number when it rebuilds them), and below main (32766)
	// so marked packets hit table 100 first.
	rulePref = "32000"

	// defaultLockPath serialises Reconcile between the daemon and the NDM
	// hook processes, which may run at the same time: position-based
	// commands inside our chains must not interleave.
	defaultLockPath = "/var/run/netshunt-rules.lock"
)

// Redirect implements Mode using NAT REDIRECT (TCP) and TPROXY (UDP)
// to a local transparent proxy port.
//
// This works with any transparent proxy that listens on a local port:
// ss-redir (-u), xray (dokodemo-door), sing-box, etc.
//
// Traffic flow:
//  1. DNS query resolved → IP added to ipset by DNS forwarder
//  2. TCP: iptables PREROUTING (nat) redirects to cfg.Routing.ActivePort()
//  3. UDP: iptables PREROUTING (mangle) TPROXY to cfg.Routing.ActivePort()
//  4. Transparent proxy forwards traffic through the tunnel
type Redirect struct {
	cfg      *config.Live
	ipt      *netfilter.IPTables
	run      platform.Runner
	logger   *slog.Logger
	lockPath string
}

// NewRedirect creates a Redirect traffic mode handler.
func NewRedirect(cfg *config.Live, logger *slog.Logger) *Redirect {
	return newRedirect(cfg, logger, platform.DefaultRunner, defaultLockPath)
}

func newRedirect(cfg *config.Live, logger *slog.Logger, run platform.Runner, lockPath string) *Redirect {
	return &Redirect{
		cfg:      cfg,
		ipt:      &netfilter.IPTables{Runner: run},
		run:      run,
		logger:   logger,
		lockPath: lockPath,
	}
}

func (r *Redirect) Name() string { return "redirect" }

// desiredRules is the complete rule set Reconcile converges to.
type desiredRules struct {
	natChain    [][]string // NSHUNT, in order
	mangleChain [][]string // NSHUNT_UDP, in order
	natPre      [][]string // our nat PREROUTING rules (jumps, then DNS)
	manglePre   [][]string // our mangle PREROUTING rules (jumps)
	ksChain     [][]string // filter NSHUNT_KS, in order
	ksJump      []string   // filter FORWARD rule 1
}

func (r *Redirect) desired() desiredRules {
	cfg := r.cfg.Load()
	ipsetName := cfg.IPSet.TableName
	port := fmt.Sprintf("%d", cfg.Routing.ActivePort())
	ifaces := cfg.Network.InterceptInterfaces()
	excluded := filterIPv4Networks(cfg.ExcludedNetworks)

	var d desiredRules
	for _, n := range excluded {
		d.natChain = append(d.natChain, []string{"-d", n, "-j", "RETURN"})
		d.mangleChain = append(d.mangleChain, []string{"-d", n, "-j", "RETURN"})
	}
	d.natChain = append(d.natChain, []string{"-p", "tcp", "-m", "set", "--match-set", ipsetName, "dst",
		"-j", "REDIRECT", "--to-ports", port})
	d.mangleChain = append(d.mangleChain, []string{"-p", "udp", "-m", "set", "--match-set", ipsetName, "dst",
		"-j", "TPROXY", "--on-port", port, "--tproxy-mark", fwmark + "/" + fwmark})

	// Kill switch (filter NSHUNT_KS, jumped to from FORWARD position 1, no
	// -i): a packet to a shunted address that reaches FORWARD is a leak by
	// definition, so it is dropped instead of leaving via the default route.
	// What it must not drop, and why it does not:
	//   - Redirected traffic: REDIRECT (nat) and TPROXY (mangle) deliver the
	//     packet locally, so it goes to INPUT and never reaches FORWARD.
	//   - Router-generated traffic (the proxy's own upstream connection, DNS
	//     to the upstreams, healthchecks) goes through OUTPUT, not FORWARD.
	//   - LAN-to-LAN or VPN traffic to the excluded networks: the same RETURN
	//     list as NSHUNT/NSHUNT_UDP comes first, so a private address that
	//     some domain resolved to is still forwarded normally.
	// What it does drop, on purpose: anything to a shunted address that was
	// not redirected, e.g. TCP/UDP from an interface netshunt does not
	// intercept, ICMP and other protocols, packets of a direct connection
	// opened before its address entered the set, and everything while the
	// nat/mangle jumps are missing. The jump is unconditional and first, so
	// neither NDM's own FORWARD rules nor the AmneziaWG ACCEPTs can let such
	// a packet through.
	for _, n := range excluded {
		d.ksChain = append(d.ksChain, []string{"-d", n, "-j", "RETURN"})
	}
	d.ksChain = append(d.ksChain, []string{"-m", "set", "--match-set", ipsetName, "dst", "-j", "DROP"})
	d.ksJump = []string{"-j", KillSwitchChain}

	if len(ifaces) == 0 {
		d.natPre = append(d.natPre, []string{"-j", redirectChainName})
		d.manglePre = append(d.manglePre, []string{"-j", redirectUDPChainName})
	}
	for _, iface := range ifaces {
		d.natPre = append(d.natPre, []string{"-i", iface, "-j", redirectChainName})
		d.manglePre = append(d.manglePre, []string{"-i", iface, "-j", redirectUDPChainName})
	}
	// DNS interception. REDIRECT rewrites the destination to the primary
	// address of the ingress interface (192.168.1.1 on br0, the TUN address
	// on awg0), which the router's INPUT chain already accepts. A DNAT to
	// 127.0.0.1 does not work here: packets that arrive on br0 with a
	// loopback destination are dropped before they reach the forwarder, so
	// clients with a hard-coded resolver got no answer at all.
	for _, iface := range cfg.Network.DNSInterfaces() {
		for _, proto := range []string{"udp", "tcp"} {
			d.natPre = append(d.natPre, DNSRedirectRule(iface, proto)[1:])
		}
	}
	return d
}

// isOurNatPrerouting reports whether a nat PREROUTING rule is one netshunt
// manages: a jump to NSHUNT or a DNS REDIRECT with our signature on any
// interface (so a removed interface's rules are found).
func isOurNatPrerouting(key string) bool {
	if strings.HasSuffix(key, "-j "+redirectChainName) {
		return true
	}
	for _, proto := range []string{"udp", "tcp"} {
		sig := canonicalRule(DNSRedirectRule("x", proto)[3:]) // without "PREROUTING -i x"
		if key == sig || (strings.HasPrefix(key, "-i ") && strings.HasSuffix(key, " "+sig) &&
			len(strings.Fields(strings.TrimSuffix(key, " "+sig))) == 2) {
			return true
		}
	}
	return false
}

func isOurManglePrerouting(key string) bool {
	return strings.HasSuffix(key, "-j "+redirectUDPChainName)
}

// Reconcile converges iptables and the TPROXY policy route to the config.
// Inside NSHUNT/NSHUNT_UDP rules are inserted or replaced in place
// (`-I`/`-R` at their position), so the chain always holds exactly one
// redirect rule, also while the port changes. In PREROUTING missing rules
// are appended before stale ones of ours are deleted. Rules netshunt does
// not own are never touched. The kill-switch jump is kept at FORWARD
// position 1. With nothing to change only reads run: `iptables -S` of the
// six chains, `ip rule show`, `ip route show`.
func (r *Redirect) Reconcile(ctx context.Context) error {
	unlock := r.lock()
	defer unlock()

	d := r.desired()

	// TCP: nat.
	if err := r.syncChain(ctx, "nat", redirectChainName, d.natChain, nil); err != nil {
		return fmt.Errorf("sync nat %s: %w", redirectChainName, err)
	}
	if err := r.syncPrerouting(ctx, "nat", d.natPre, isOurNatPrerouting); err != nil {
		return fmt.Errorf("sync nat PREROUTING: %w", err)
	}

	// Kill switch: before UDP, so that a missing TPROXY fails closed.
	if err := r.syncChain(ctx, "filter", KillSwitchChain, d.ksChain, nil); err != nil {
		return fmt.Errorf("sync filter %s: %w", KillSwitchChain, err)
	}
	if err := r.syncFirstRule(ctx, "filter", "FORWARD", d.ksJump); err != nil {
		return fmt.Errorf("sync filter FORWARD: %w", err)
	}

	// UDP: TPROXY via mangle. Mandatory: UDP to a shunted address must
	// never go direct because TPROXY could not be installed, so a failure
	// here fails the whole Reconcile (the TCP rules above stay converged).
	if err := r.syncUDP(ctx, d); err != nil {
		return fmt.Errorf("udp tproxy: %w", err)
	}
	return nil
}

func (r *Redirect) syncUDP(ctx context.Context, d desiredRules) error {
	if err := r.syncChain(ctx, "mangle", redirectUDPChainName, d.mangleChain, r.ensureTproxyModule); err != nil {
		return fmt.Errorf("sync mangle %s: %w", redirectUDPChainName, err)
	}
	if err := r.syncPrerouting(ctx, "mangle", d.manglePre, isOurManglePrerouting); err != nil {
		return fmt.Errorf("sync mangle PREROUTING: %w", err)
	}
	// Policy routing for TPROXY-marked packets. "ip rule add" is not
	// idempotent, so check first and pin the priority so teardown can
	// remove exactly this rule.
	if !r.policyRuleExists(ctx) {
		if err := r.mutate(ctx, "ip", "rule", "add", "pref", rulePref, "fwmark", fwmark, "table", routeTable); err != nil {
			return fmt.Errorf("ip rule add: %w", err)
		}
	}
	if !r.localRouteExists(ctx) {
		if err := r.mutate(ctx, "ip", "route", "replace", "local", "0/0", "dev", "lo", "table", routeTable); err != nil {
			return fmt.Errorf("ip route replace: %w", err)
		}
	}
	return nil
}

// mutate runs and logs one state-changing command.
func (r *Redirect) mutate(ctx context.Context, name string, args ...string) error {
	r.logger.Info("rule change", "cmd", name+" "+strings.Join(args, " "))
	return r.run.RunSilent(ctx, name, args...)
}

func (r *Redirect) iptMutate(ctx context.Context, table string, args ...string) error {
	return r.mutate(ctx, "iptables", append([]string{"-w", "-t", table}, args...)...)
}

// syncChain makes chain hold exactly desired, in order. beforeTproxy, when
// set, runs once before a TPROXY rule is written into a chain that has none
// yet (it loads the kernel module).
//
// Walking the desired list: a matching rule is kept; a stale rule standing
// where a desired one belongs is replaced in place (`-R`) when neither is
// needed elsewhere; a stale rule in front of a desired one that exists
// further down is deleted; otherwise the desired rule is inserted at its
// position (`-I`). Leftovers past the end are deleted bottom-up. Every
// iptables command commits atomically, so the chain never lacks the
// redirect rule and never holds two.
func (r *Redirect) syncChain(ctx context.Context, table, chain string, desired [][]string, beforeTproxy func(context.Context)) error {
	out, err := r.ipt.Save(ctx, table, chain)
	if err != nil {
		if nerr := r.iptMutate(ctx, table, "-N", chain); nerr != nil {
			return fmt.Errorf("read chain: %w; create chain: %w", err, nerr)
		}
		out = ""
	}
	cur := parseSave(out, chain)

	moduleReady := beforeTproxy == nil
	for _, x := range cur {
		if slices.Contains(x.spec, "TPROXY") {
			moduleReady = true
		}
	}
	change := func(spec []string) {
		if !moduleReady && slices.Contains(spec, "TPROXY") {
			beforeTproxy(ctx)
			moduleReady = true
		}
	}

	keys := make([]string, len(desired))
	for i, spec := range desired {
		keys[i] = canonicalRule(spec)
	}
	countIn := func(key string, rules []savedRule) int {
		n := 0
		for _, x := range rules {
			if x.key == key {
				n++
			}
		}
		return n
	}
	countKeys := func(key string, ks []string) int {
		n := 0
		for _, k := range ks {
			if k == key {
				n++
			}
		}
		return n
	}

	for i := 0; i < len(desired); {
		want := keys[i]
		if i < len(cur) && cur[i].key == want {
			i++
			continue
		}
		pos := fmt.Sprintf("%d", i+1)
		if i < len(cur) {
			staleNeededLater := countKeys(cur[i].key, keys[i+1:]) > 0
			wantLater := countIn(want, cur[i+1:]) > 0
			switch {
			case !staleNeededLater && !wantLater:
				change(desired[i])
				if err := r.iptMutate(ctx, table, append([]string{"-R", chain, pos}, desired[i]...)...); err != nil {
					return err
				}
				cur[i] = savedRule{spec: desired[i], key: want}
				i++
				continue
			case !staleNeededLater && wantLater:
				if err := r.iptMutate(ctx, table, "-D", chain, pos); err != nil {
					return err
				}
				cur = append(cur[:i:i], cur[i+1:]...)
				continue
			}
		}
		change(desired[i])
		if err := r.iptMutate(ctx, table, append([]string{"-I", chain, pos}, desired[i]...)...); err != nil {
			return err
		}
		cur = append(cur[:i:i], append([]savedRule{{spec: desired[i], key: want}}, cur[i:]...)...)
		i++
	}
	for n := len(cur); n > len(desired); n-- {
		if err := r.iptMutate(ctx, table, "-D", chain, fmt.Sprintf("%d", n)); err != nil {
			return err
		}
	}
	return nil
}

// syncPrerouting makes the rules of ours in PREROUTING equal desired: missing
// ones are appended first, then stale or duplicate ones of ours deleted by
// spec. Rules for which ours returns false are never touched; their
// positions do not matter since nothing here deletes by number.
func (r *Redirect) syncPrerouting(ctx context.Context, table string, desired [][]string, ours func(key string) bool) error {
	out, err := r.ipt.Save(ctx, table, "PREROUTING")
	if err != nil {
		return err
	}
	cur := parseSave(out, "PREROUTING")

	have := map[string]int{}
	for _, x := range cur {
		have[x.key]++
	}
	want := map[string]bool{}
	for _, spec := range desired {
		key := canonicalRule(spec)
		if want[key] {
			continue
		}
		want[key] = true
		if have[key] == 0 {
			if err := r.iptMutate(ctx, table, append([]string{"-A", "PREROUTING"}, spec...)...); err != nil {
				return err
			}
		}
	}

	kept := map[string]bool{}
	for _, x := range cur {
		if !ours(x.key) {
			continue
		}
		if want[x.key] && !kept[x.key] {
			kept[x.key] = true
			continue
		}
		if err := r.iptMutate(ctx, table, append([]string{"-D", "PREROUTING"}, x.spec...)...); err != nil {
			return err
		}
	}
	return nil
}

// syncFirstRule makes spec the first rule of a built-in chain shared with
// NDM (FORWARD) and the only copy of it there. When it is not first it is
// inserted at 1 before any other copy is deleted, so the chain never lacks
// it. Copies are deleted by number, which is the only way to delete a copy
// that is not the first match; FORWARD is rewritten by NDM, so the chain is
// re-read before every delete and the number checked against it. With the
// rule already first and unique this is one read.
func (r *Redirect) syncFirstRule(ctx context.Context, table, chain string, spec []string) error {
	key := canonicalRule(spec)
	out, err := r.ipt.Save(ctx, table, chain)
	if err != nil {
		return err
	}
	cur := parseSave(out, chain)
	if len(cur) == 0 || cur[0].key != key {
		if err := r.iptMutate(ctx, table, append([]string{"-I", chain, "1"}, spec...)...); err != nil {
			return err
		}
		cur = append([]savedRule{{spec: spec, key: key}}, cur...)
	}
	lastCopy := func(rules []savedRule) int {
		for i := len(rules) - 1; i > 0; i-- {
			if rules[i].key == key {
				return i
			}
		}
		return -1
	}
	for n := lastCopy(cur); n > 0; n = lastCopy(cur) {
		out, err := r.ipt.Save(ctx, table, chain)
		if err != nil {
			return err
		}
		cur = parseSave(out, chain)
		if n = lastCopy(cur); n < 0 {
			break
		}
		if err := r.iptMutate(ctx, table, "-D", chain, fmt.Sprintf("%d", n+1)); err != nil {
			return err
		}
		cur = append(cur[:n:n], cur[n+1:]...)
	}
	return nil
}

func isOurForward(key string) bool {
	return key == canonicalRule([]string{"-j", KillSwitchChain})
}

// ensureTproxyModule loads xt_TPROXY before the TPROXY rule is installed.
// On Keenetic routers modprobe is not available, so it falls back to insmod.
func (r *Redirect) ensureTproxyModule(ctx context.Context) {
	if r.run.RunSilent(ctx, "modprobe", "xt_TPROXY") == nil {
		return
	}
	rel, err := r.run.Run(ctx, "uname", "-r")
	if err != nil {
		return
	}
	_ = r.run.RunSilent(ctx, "insmod", "/lib/modules/"+strings.TrimSpace(rel)+"/xt_TPROXY.ko")
}

// policyRuleExists reports whether the fwmark policy rule is already
// installed at rulePref.
func (r *Redirect) policyRuleExists(ctx context.Context) bool {
	return policyRuleExists(ctx, r.run)
}

// localRouteExists reports whether table 100 routes everything to lo.
func (r *Redirect) localRouteExists(ctx context.Context) bool {
	return localRouteExists(ctx, r.run)
}

// TproxyRoutePresent reports whether the policy rule and the local route
// that deliver TPROXY-marked packets to the proxy socket are installed.
// Shared with the healthcheck.
func TproxyRoutePresent(ctx context.Context, run platform.Runner) bool {
	run = platform.OrDefault(run)
	return policyRuleExists(ctx, run) && localRouteExists(ctx, run)
}

// policyRuleExists: "ip rule show" prints one rule per line as
// "<pref>:\tfrom all fwmark 0x1 lookup 100".
func policyRuleExists(ctx context.Context, run platform.Runner) bool {
	out, err := run.Run(ctx, "ip", "rule", "show")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, rulePref+":") &&
			strings.Contains(line, "fwmark "+fwmark+" ") &&
			strings.Contains(line, "lookup "+routeTable) {
			return true
		}
	}
	return false
}

// localRouteExists: table 100 routes everything to lo
// ("local default dev lo scope host").
func localRouteExists(ctx context.Context, run platform.Runner) bool {
	out, err := run.Run(ctx, "ip", "route", "show", "table", routeTable)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[0] == "local" && (f[1] == "default" || f[1] == "0.0.0.0/0") &&
			f[2] == "dev" && f[3] == "lo" {
			return true
		}
	}
	return false
}

// lock takes an exclusive flock on lockPath. Failing to open the lock file
// (e.g. no /var/run on a dev machine) proceeds unlocked.
func (r *Redirect) lock() func() {
	if r.lockPath == "" {
		return func() {}
	}
	f, err := os.OpenFile(r.lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return func() {}
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}
}

// TeardownRules removes TCP/UDP redirect chains, the kill switch, policy
// routing, and DNS redirect rules (uninstall).
func (r *Redirect) TeardownRules(ctx context.Context) error {
	unlock := r.lock()
	defer unlock()
	r.logger.Info("tearing down redirect rules")

	for _, t := range []struct{ table, chain string }{
		{"nat", redirectChainName},
		{"mangle", redirectUDPChainName},
	} {
		ours := isOurManglePrerouting
		if t.table == "nat" {
			ours = isOurNatPrerouting
		}
		if out, err := r.ipt.Save(ctx, t.table, "PREROUTING"); err == nil {
			for _, x := range parseSave(out, "PREROUTING") {
				if ours(x.key) {
					_ = r.iptMutate(ctx, t.table, append([]string{"-D", "PREROUTING"}, x.spec...)...)
				}
			}
		}
		if _, err := r.ipt.Save(ctx, t.table, t.chain); err == nil {
			_ = r.iptMutate(ctx, t.table, "-F", t.chain)
			_ = r.iptMutate(ctx, t.table, "-X", t.chain)
		}
	}

	// Kill switch last: until here a packet to a shunted address that is no
	// longer redirected is still dropped. The ipset can only be destroyed
	// after this rule, which references it, is gone.
	if out, err := r.ipt.Save(ctx, "filter", "FORWARD"); err == nil {
		for _, x := range parseSave(out, "FORWARD") {
			if isOurForward(x.key) {
				_ = r.iptMutate(ctx, "filter", append([]string{"-D", "FORWARD"}, x.spec...)...)
			}
		}
	}
	if _, err := r.ipt.Save(ctx, "filter", KillSwitchChain); err == nil {
		_ = r.iptMutate(ctx, "filter", "-F", KillSwitchChain)
		_ = r.iptMutate(ctx, "filter", "-X", KillSwitchChain)
	}

	if r.policyRuleExists(ctx) {
		_ = r.mutate(ctx, "ip", "rule", "del", "pref", rulePref, "fwmark", fwmark, "table", routeTable)
	}
	if r.localRouteExists(ctx) {
		_ = r.mutate(ctx, "ip", "route", "del", "local", "0/0", "table", routeTable)
	}
	return nil
}

// IsActive checks if something is listening on the configured local port.
func (r *Redirect) IsActive(ctx context.Context) (bool, error) {
	port := fmt.Sprintf(":%d", r.cfg.Load().Routing.ActivePort())
	ok, err := netfilter.CheckListeningPort(ctx, port)
	if err != nil {
		return false, nil
	}
	return ok, nil
}

// filterIPv4Networks returns only the IPv4 CIDRs from the input.
// Validation at the form layer rejects v6 entries, but legacy configs may
// still contain them - skip silently to avoid breaking startup.
func filterIPv4Networks(networks []string) []string {
	var out []string
	for _, n := range networks {
		_, cidr, err := net.ParseCIDR(n)
		if err != nil {
			continue
		}
		if cidr.IP.To4() != nil {
			out = append(out, n)
		}
	}
	return out
}

// DNSRedirectRule is the nat PREROUTING rule that steers port-53 traffic from
// iface to the local forwarder. Shared by reconcile, teardown and the
// healthcheck so all three agree on the exact rule signature.
func DNSRedirectRule(iface, proto string) []string {
	return []string{"PREROUTING", "-i", iface, "-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"}
}
