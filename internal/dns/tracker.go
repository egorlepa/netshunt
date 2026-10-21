package dns

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/egorlepa/netshunt/internal/platform"
)

// IPSetOps is the subset of netfilter.IPSet the Tracker drives. It exists so
// tests can substitute a fake that records calls instead of exec'ing ipset.
type IPSetOps interface {
	Add(ctx context.Context, entry string) error
	Del(ctx context.Context, entry string) error
	Flush(ctx context.Context) error
	List(ctx context.Context) ([]string, error)
}

// Tracker owns the kernel ipset: every member of the set is either an IP a
// DNS answer resolved for a tracked domain, or a static IP/CIDR entry from an
// enabled shunt. The in-memory maps are the source of truth for what the
// kernel holds, so an IP already present is never re-added.
//
// References are counted per member: a member stays in the ipset while at
// least one domain or a static entry references it, and leaves as soon as the
// last reference goes. IPs are retained until the domain is explicitly
// removed or the tracker is flushed; DNS TTL is intentionally ignored to
// prevent long-lived connections from losing routing mid-session.
//
// Locking: mu guards the maps and is never held across an exec. kernelMu
// serialises every slow path that changes kernel membership (decide under mu,
// exec, commit under mu), so a concurrent add and delete of the same member
// cannot leave the maps and the kernel disagreeing. The Track fast path (member
// already present) takes only mu.
type Tracker struct {
	kernelMu sync.Mutex
	mu       sync.RWMutex
	forward  map[string][]string // domain -> IPs (typically 1-4)
	reverse  map[string][]string // IP -> domains (typically 1-2)
	static   map[string]struct{} // static IP/CIDR members, canonical form
	ipset    IPSetOps
	logger   *slog.Logger

	// flushConntrack drops conntrack entries for a member (IP or CIDR).
	// Replaceable in tests.
	flushConntrack func(ctx context.Context, member string)
}

// NewTracker creates a Tracker that manages the given ipset table.
func NewTracker(ipset IPSetOps, logger *slog.Logger) *Tracker {
	t := &Tracker{
		forward: make(map[string][]string),
		reverse: make(map[string][]string),
		static:  make(map[string]struct{}),
		ipset:   ipset,
		logger:  logger,
	}
	t.flushConntrack = t.runConntrackFlush
	return t
}

// presentLocked reports whether member is in the kernel ipset according to
// the maps. Caller holds mu (read or write).
func (t *Tracker) presentLocked(member string) bool {
	if len(t.reverse[member]) > 0 {
		return true
	}
	_, ok := t.static[member]
	return ok
}

// linkLocked records the domain<->ip reference. Caller holds mu.
func (t *Tracker) linkLocked(domain, ip string) {
	if ips := t.forward[domain]; !slices.Contains(ips, ip) {
		t.forward[domain] = append(ips, ip)
	}
	if refs := t.reverse[ip]; !slices.Contains(refs, domain) {
		t.reverse[ip] = append(refs, domain)
	}
}

// Track records an IP for a domain. If the IP is already in the ipset (another
// domain or a static entry holds it), only the reference is recorded and no
// process is spawned. Otherwise the IP is added to the kernel ipset first and
// the maps are updated only if that succeeded; a failed add leaves the maps
// untouched so the next DNS answer retries. When the IP becomes newly present,
// conntrack entries with that orig-dst are flushed so existing direct
// connections reopen through the proxy.
func (t *Tracker) Track(ctx context.Context, domain, ip string) {
	t.mu.Lock()
	if t.presentLocked(ip) {
		t.linkLocked(domain, ip)
		t.mu.Unlock()
		return
	}
	t.mu.Unlock()

	t.kernelMu.Lock()
	t.mu.Lock()
	if t.presentLocked(ip) {
		// Added by a concurrent caller while we waited for kernelMu.
		t.linkLocked(domain, ip)
		t.mu.Unlock()
		t.kernelMu.Unlock()
		return
	}
	t.mu.Unlock()

	if err := t.ipset.Add(ctx, ip); err != nil {
		t.kernelMu.Unlock()
		t.logger.Warn("tracker: ipset add failed", "ip", ip, "domain", domain, "error", err)
		return
	}
	t.mu.Lock()
	t.linkLocked(domain, ip)
	t.mu.Unlock()
	t.kernelMu.Unlock()

	t.flushConntrack(ctx, ip)
}

// RemoveDomain removes all IPs associated with a domain. IPs no longer
// referenced by any domain or static entry are removed from the ipset.
func (t *Tracker) RemoveDomain(ctx context.Context, domain string) {
	t.kernelMu.Lock()
	t.mu.Lock()
	ips := t.forward[domain]
	delete(t.forward, domain)

	var toRemove []string
	for _, ip := range ips {
		refs := slices.DeleteFunc(t.reverse[ip], func(d string) bool { return d == domain })
		if len(refs) == 0 {
			delete(t.reverse, ip)
			if _, isStatic := t.static[ip]; !isStatic {
				toRemove = append(toRemove, ip)
			}
		} else {
			t.reverse[ip] = refs
		}
	}
	t.mu.Unlock()

	t.delMembersLocked(ctx, toRemove)
	t.kernelMu.Unlock()

	// Drop live connections to these IPs so clients reconnect directly (no
	// longer through the proxy) on the next request.
	for _, ip := range toRemove {
		t.flushConntrack(ctx, ip)
	}
}

// delMembersLocked execs ipset del for each member. A failed del leaves an
// unexplained member in the kernel; the full-reconcile repair pass removes it.
// Caller holds kernelMu.
func (t *Tracker) delMembersLocked(ctx context.Context, members []string) {
	for _, m := range members {
		if err := t.ipset.Del(ctx, m); err != nil {
			t.logger.Warn("tracker: ipset del failed", "member", m, "error", err)
		}
	}
}

// SetStatic replaces the set of static IP/CIDR entries (IPv4 only, from
// enabled shunts). Entries are canonicalised (1.2.3.4/32 -> 1.2.3.4, host
// bits masked), so a static IP and a DNS-tracked IP share one reference count.
// An entry newly present in the ipset is added and its conntrack flushed; an
// entry no longer referenced by anything is deleted and its conntrack flushed.
// A static entry whose IP a domain already holds (or keeps holding) changes
// no kernel state. A failed add leaves the entry out of the static set, so
// the next call retries it.
func (t *Tracker) SetStatic(ctx context.Context, values []string) {
	want := make(map[string]struct{}, len(values))
	for _, v := range values {
		m, ok := canonicalMember(v)
		if !ok {
			t.logger.Warn("tracker: skipping unparsable static entry", "entry", v)
			continue
		}
		want[m] = struct{}{}
	}

	t.kernelMu.Lock()
	t.mu.Lock()
	var toAdd, toRemove []string
	for m := range want {
		if _, ok := t.static[m]; ok {
			continue
		}
		if len(t.reverse[m]) > 0 {
			t.static[m] = struct{}{} // already in the kernel via a domain
			continue
		}
		toAdd = append(toAdd, m)
	}
	for m := range t.static {
		if _, ok := want[m]; ok {
			continue
		}
		delete(t.static, m)
		if len(t.reverse[m]) == 0 {
			toRemove = append(toRemove, m)
		}
	}
	t.mu.Unlock()

	var added []string
	for _, m := range toAdd {
		if err := t.ipset.Add(ctx, m); err != nil {
			t.logger.Warn("tracker: ipset add failed", "member", m, "error", err)
			continue
		}
		added = append(added, m)
	}
	t.mu.Lock()
	for _, m := range added {
		t.static[m] = struct{}{}
	}
	t.mu.Unlock()
	t.delMembersLocked(ctx, toRemove)
	t.kernelMu.Unlock()

	for _, m := range added {
		t.flushConntrack(ctx, m)
	}
	for _, m := range toRemove {
		t.flushConntrack(ctx, m)
	}
}

// Repair makes the kernel ipset equal the tracker's members with exactly one
// `ipset list`: members the tracker knows but the kernel lacks are re-added,
// members the kernel holds but nothing references are deleted. A member that
// cannot be re-added is forgotten, so the maps keep matching the kernel and
// the next DNS answer (or SetStatic) retries it. This is the only place that
// heals external interference such as a manual `ipset flush`.
func (t *Tracker) Repair(ctx context.Context) (added, removed int, err error) {
	t.kernelMu.Lock()
	defer t.kernelMu.Unlock()

	kernel, err := t.ipset.List(ctx)
	if err != nil {
		return 0, 0, err
	}

	t.mu.RLock()
	known := make(map[string]struct{}, len(t.reverse)+len(t.static))
	for ip := range t.reverse {
		known[ip] = struct{}{}
	}
	for m := range t.static {
		known[m] = struct{}{}
	}
	t.mu.RUnlock()

	missing, unknown := diffMembers(known, kernel)

	var failed []string
	for _, m := range missing {
		if err := t.ipset.Add(ctx, m); err != nil {
			t.logger.Warn("tracker: repair add failed, forgetting member", "member", m, "error", err)
			failed = append(failed, m)
			continue
		}
		added++
	}
	if len(failed) > 0 {
		t.mu.Lock()
		for _, m := range failed {
			t.forgetLocked(m)
		}
		t.mu.Unlock()
	}
	for _, m := range unknown {
		if err := t.ipset.Del(ctx, m); err != nil {
			t.logger.Warn("tracker: repair del failed", "member", m, "error", err)
			continue
		}
		removed++
	}

	// Re-added members may have carried direct connections during the gap;
	// removed ones may carry proxied connections. Either way, reopen them.
	for _, m := range missing {
		if !slices.Contains(failed, m) {
			t.flushConntrack(ctx, m)
		}
	}
	for _, m := range unknown {
		t.flushConntrack(ctx, m)
	}
	return added, removed, nil
}

// forgetLocked drops every reference to member. Caller holds mu.
func (t *Tracker) forgetLocked(member string) {
	for _, d := range t.reverse[member] {
		ips := slices.DeleteFunc(t.forward[d], func(ip string) bool { return ip == member })
		if len(ips) == 0 {
			delete(t.forward, d)
		} else {
			t.forward[d] = ips
		}
	}
	delete(t.reverse, member)
	delete(t.static, member)
}

// diffMembers compares the tracker's known members with an `ipset list`
// output. missing: known but absent from the kernel. unknown: in the kernel
// but not known. Kernel entries are canonicalised before comparison; both
// results are sorted.
func diffMembers(known map[string]struct{}, kernel []string) (missing, unknown []string) {
	inKernel := make(map[string]struct{}, len(kernel))
	for _, line := range kernel {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		m, ok := canonicalMember(fields[0])
		if !ok {
			m = fields[0]
		}
		if _, dup := inKernel[m]; dup {
			continue
		}
		inKernel[m] = struct{}{}
		if _, ok := known[m]; !ok {
			unknown = append(unknown, m)
		}
	}
	for m := range known {
		if _, ok := inKernel[m]; !ok {
			missing = append(missing, m)
		}
	}
	slices.Sort(missing)
	slices.Sort(unknown)
	return missing, unknown
}

// canonicalMember returns the form `ipset list` prints for an IPv4 hash:net
// member: a bare address for a host (/32), network/bits with host bits
// cleared otherwise.
func canonicalMember(v string) (string, bool) {
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return "", false
		}
		p = p.Masked()
		if p.Addr().Is4() && p.Bits() == 32 {
			return p.Addr().String(), true
		}
		return p.String(), true
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return "", false
	}
	return a.String(), true
}

// runConntrackFlush drops conntrack entries whose orig-dst falls within the
// given IP or CIDR. Best-effort; logged at debug on failure (commonly the
// "no matches" exit code).
func (t *Tracker) runConntrackFlush(ctx context.Context, member string) {
	args := []string{"-D", "--orig-dst", member}
	if p, err := netip.ParsePrefix(member); err == nil {
		mask := net.IP(net.CIDRMask(p.Bits(), 32)).String()
		args = []string{"-D", "--orig-dst", p.Masked().Addr().String(), "--mask-dst", mask}
	}
	if err := platform.RunSilent(ctx, "conntrack", args...); err != nil {
		t.logger.Debug("conntrack flush returned non-zero (likely no matches)", "member", member, "error", err)
	}
}

// Flush clears all tracked state (domains and static entries) and flushes
// the ipset.
func (t *Tracker) Flush(ctx context.Context) error {
	t.kernelMu.Lock()
	defer t.kernelMu.Unlock()
	t.mu.Lock()
	t.forward = make(map[string][]string)
	t.reverse = make(map[string][]string)
	t.static = make(map[string]struct{})
	t.mu.Unlock()

	if err := t.ipset.Flush(ctx); err != nil {
		t.logger.Warn("tracker: ipset flush failed", "error", err)
		return err
	}
	return nil
}

// Count returns the number of tracked domains and the unique IPs they
// reference. Static entries are not counted.
func (t *Tracker) Count() (domains int, ips int) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.forward), len(t.reverse)
}
