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

// IPSetBatchOps is implemented by ipsets that can apply many members in one
// process (`ipset restore`). The tracker uses it for every multi-member
// change (static sets, sweeps, repair); the DNS path stays one Add per IP.
type IPSetBatchOps interface {
	AddBatch(ctx context.Context, members []string) error
	DelBatch(ctx context.Context, members []string) error
}

// addMembers adds members to the kernel set and returns those that are now
// present and those that failed. One batch exec when the set supports it;
// since restore applies a prefix and stops on the first error, a failed
// batch is retried member by member (idempotent with -exist) so the result
// is exact.
func (t *Tracker) addMembers(ctx context.Context, members []string) (ok, failed []string) {
	if len(members) == 0 {
		return nil, nil
	}
	if b, can := t.ipset.(IPSetBatchOps); can && len(members) > 1 {
		if err := b.AddBatch(ctx, members); err == nil {
			return members, nil
		} else {
			t.logger.Warn("tracker: ipset batch add failed, retrying one by one", "members", len(members), "error", err)
		}
	}
	for _, m := range members {
		if err := t.ipset.Add(ctx, m); err != nil {
			t.logger.Warn("tracker: ipset add failed", "member", m, "error", err)
			failed = append(failed, m)
			continue
		}
		ok = append(ok, m)
	}
	return ok, failed
}

// delMembers is the removal counterpart of addMembers.
func (t *Tracker) delMembers(ctx context.Context, members []string) (ok, failed []string) {
	if len(members) == 0 {
		return nil, nil
	}
	if b, can := t.ipset.(IPSetBatchOps); can && len(members) > 1 {
		if err := b.DelBatch(ctx, members); err == nil {
			return members, nil
		} else {
			t.logger.Warn("tracker: ipset batch del failed, retrying one by one", "members", len(members), "error", err)
		}
	}
	for _, m := range members {
		if err := t.ipset.Del(ctx, m); err != nil {
			t.logger.Warn("tracker: ipset del failed", "member", m, "error", err)
			failed = append(failed, m)
			continue
		}
		ok = append(ok, m)
	}
	return ok, failed
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
	// orphans are members the maps no longer reference whose `ipset del`
	// failed (e.g. a cancelled context). They are still in the kernel, so
	// RetryOrphans deletes them on the next mutation; Repair and Flush
	// clear them.
	orphans map[string]struct{}
	ipset   IPSetOps
	logger  *slog.Logger

	// Runner executes conntrack; nil means platform.DefaultRunner.
	Runner platform.Runner

	// flushConntrack drops conntrack entries for a member (IP or CIDR).
	// Replaceable in tests.
	flushConntrack func(ctx context.Context, member string)

	// persist, when set, saves the domain map to disk (EnablePersistence).
	persist *persister
}

// NewTracker creates a Tracker that manages the given ipset table.
func NewTracker(ipset IPSetOps, logger *slog.Logger) *Tracker {
	t := &Tracker{
		forward: make(map[string][]string),
		reverse: make(map[string][]string),
		static:  make(map[string]struct{}),
		orphans: make(map[string]struct{}),
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
		t.markDirty()
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
	delete(t.orphans, ip)
	t.mu.Unlock()
	t.kernelMu.Unlock()

	t.flushConntrack(ctx, ip)
}

// RemoveDomain removes all IPs associated with a domain. IPs no longer
// referenced by any domain or static entry are removed from the ipset.
func (t *Tracker) RemoveDomain(ctx context.Context, domain string) {
	t.kernelMu.Lock()
	t.mu.Lock()
	ips, ok := t.forward[domain]
	if ok {
		delete(t.forward, domain)
		t.markDirty()
	}

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
// unexplained member in the kernel: it is recorded as an orphan so the next
// RetryOrphans (every mutation) or Repair (full reconcile) removes it.
// Caller holds kernelMu.
func (t *Tracker) delMembersLocked(ctx context.Context, members []string) {
	_, failed := t.delMembers(ctx, members)
	if len(failed) == 0 {
		return
	}
	t.mu.Lock()
	for _, m := range failed {
		if !t.presentLocked(m) {
			t.orphans[m] = struct{}{}
		}
	}
	t.mu.Unlock()
}

// RetryOrphans deletes members whose earlier `ipset del` failed and that
// nothing has referenced since. Cheap when there are none (no exec).
func (t *Tracker) RetryOrphans(ctx context.Context) {
	t.kernelMu.Lock()
	t.mu.Lock()
	var todo []string
	for m := range t.orphans {
		if t.presentLocked(m) {
			delete(t.orphans, m)
			continue
		}
		todo = append(todo, m)
	}
	t.mu.Unlock()
	slices.Sort(todo)
	done, _ := t.delMembers(ctx, todo)
	t.mu.Lock()
	for _, m := range done {
		delete(t.orphans, m)
	}
	t.mu.Unlock()
	t.kernelMu.Unlock()
	for _, m := range done {
		t.flushConntrack(ctx, m)
	}
}

// Domains returns a snapshot of every tracked domain (the lowercase DNS
// query names), in unspecified order.
func (t *Tracker) Domains() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]string, 0, len(t.forward))
	for d := range t.forward {
		out = append(out, d)
	}
	return out
}

// Members returns the number of members the tracker believes the kernel
// ipset holds (domain-referenced IPs plus static entries).
func (t *Tracker) Members() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n := len(t.reverse)
	for m := range t.static {
		if len(t.reverse[m]) == 0 {
			n++
		}
	}
	return n
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
	t.setStatic(ctx, values, false)
}

// PresumeStatic records static entries as present in the kernel WITHOUT
// exec or conntrack flush, like LoadPersisted does for domains: on a daemon
// restart they are still in the set and their connections already go
// through the proxy. Repair afterwards re-adds what the kernel lacks. Call
// on a tracker with no static entries (cold start), before SetStatic.
func (t *Tracker) PresumeStatic(values []string) {
	t.setStatic(context.Background(), values, true)
}

func (t *Tracker) setStatic(ctx context.Context, values []string, presume bool) {
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

	if presume {
		t.mu.Lock()
		for _, m := range toAdd {
			t.static[m] = struct{}{}
		}
		t.mu.Unlock()
		t.delMembersLocked(ctx, toRemove)
		t.kernelMu.Unlock()
		return
	}

	added, _ := t.addMembers(ctx, toAdd)
	t.mu.Lock()
	for _, m := range added {
		t.static[m] = struct{}{}
		delete(t.orphans, m)
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

	t.mu.Lock()
	known := make(map[string]struct{}, len(t.reverse)+len(t.static))
	for ip := range t.reverse {
		known[ip] = struct{}{}
	}
	for m := range t.static {
		known[m] = struct{}{}
	}
	// Orphans are in the kernel but not known: diffMembers reports them as
	// unknown and they are deleted below.
	t.orphans = make(map[string]struct{})
	t.mu.Unlock()

	missing, unknown := diffMembers(known, kernel)
	t.logger.Info("ipset members", "kernel", len(kernel), "tracked", len(known),
		"missing", len(missing), "unknown", len(unknown))

	okAdd, failed := t.addMembers(ctx, missing)
	added = len(okAdd)
	if len(failed) > 0 {
		t.logger.Warn("tracker: repair could not re-add members, forgetting them", "count", len(failed))
		t.mu.Lock()
		for _, m := range failed {
			t.forgetLocked(m)
		}
		t.mu.Unlock()
	}
	okDel, _ := t.delMembers(ctx, unknown)
	removed = len(okDel)

	// Re-added members may have carried direct connections during the gap;
	// removed ones may carry proxied connections. Either way, reopen them.
	for _, m := range okAdd {
		t.flushConntrack(ctx, m)
	}
	for _, m := range okDel {
		t.flushConntrack(ctx, m)
	}
	return added, removed, nil
}

// forgetLocked drops every reference to member. Caller holds mu.
func (t *Tracker) forgetLocked(member string) {
	if len(t.reverse[member]) > 0 {
		t.markDirty()
	}
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
	if err := platform.OrDefault(t.Runner).RunSilent(ctx, "conntrack", args...); err != nil {
		t.logger.Debug("conntrack flush returned non-zero (likely no matches)", "member", member, "error", err)
	}
}

// Flush clears all tracked state (domains and static entries) and flushes
// the ipset. Not used on daemon start: the cold reconcile loads the saved
// state and repairs instead, so the set never empties across a restart.
func (t *Tracker) Flush(ctx context.Context) error {
	t.kernelMu.Lock()
	defer t.kernelMu.Unlock()
	t.mu.Lock()
	if len(t.forward) > 0 {
		t.markDirty()
	}
	t.forward = make(map[string][]string)
	t.reverse = make(map[string][]string)
	t.static = make(map[string]struct{})
	t.orphans = make(map[string]struct{})
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
