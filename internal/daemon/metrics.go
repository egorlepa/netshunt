package daemon

import (
	"github.com/egorlepa/netshunt/internal/metrics"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/platform"
)

// Collect adds the reconciler's metrics: runs per kind and result, the last
// run's duration and success time, the repair pass counts and the domains
// per enabled blocklist source in the installed matcher. Reads atomics
// only, never r.mu: a scrape must not wait for a reconcile.
func (r *Reconciler) Collect(e *metrics.Emitter) {
	for _, k := range []struct {
		name string
		s    *reconcileKindStats
	}{{"mutation", &r.stats.mutation}, {"full", &r.stats.full}} {
		e.Counter("netshunt_reconcile_total", "Reconciles by kind (mutation: shunt change, full: startup/WAN/settings/action) and result.",
			float64(k.s.ok.Load()), metrics.L("kind", k.name, "result", "ok")...)
		e.Counter("netshunt_reconcile_total", "Reconciles by kind (mutation: shunt change, full: startup/WAN/settings/action) and result.",
			float64(k.s.failed.Load()), metrics.L("kind", k.name, "result", "error")...)
		e.Gauge("netshunt_reconcile_last_duration_seconds", "Duration of the last reconcile of this kind, successful or not.",
			k.s.lastDuration.Load(), metrics.L("kind", k.name)...)
		e.Gauge("netshunt_reconcile_last_success_timestamp_seconds", "Unix time of the last successful reconcile of this kind; 0 until the first one since start.",
			k.s.lastSuccess.Load(), metrics.L("kind", k.name)...)
	}
	e.Counter("netshunt_ipset_repair_added_total", "Members the full reconcile repair pass re-added to the kernel ipset.", float64(r.stats.repairAdded.Load()))
	e.Counter("netshunt_ipset_repair_removed_total", "Members the full reconcile repair pass deleted from the kernel ipset.", float64(r.stats.repairRemoved.Load()))

	const blHelp = "Domains each enabled blocklist source contributes to the active blocklist (0 when its file is unreadable or empty)."
	e.Declare("netshunt_blocklist_source_domains", blHelp, metrics.TypeGauge)
	if counts := r.blocklistCounts.Load(); counts != nil {
		for _, c := range *counts {
			e.Gauge("netshunt_blocklist_source_domains", blHelp, float64(c.count), metrics.L("source", c.id)...)
		}
	}
}

// netfilterCollector reports the backend each netfilter component uses now:
// 1 for the current one, 0 for the other (netlink can switch to exec at
// runtime, never back).
func netfilterCollector(ipset *netfilter.IPSet, conntrack *netfilter.Conntrack) metrics.Collector {
	return func(e *metrics.Emitter) {
		for _, c := range []struct {
			component, backend string
		}{{"ipset", ipset.Backend()}, {"conntrack", conntrack.Backend()}} {
			for _, b := range []string{netfilter.BackendNetlink, netfilter.BackendExec} {
				v := 0.0
				if b == c.backend {
					v = 1
				}
				e.Gauge("netshunt_netfilter_backend", "Backend the netfilter component currently uses (1 = current).", v,
					metrics.L("component", c.component, "backend", b)...)
			}
		}
	}
}

// logCollector reports the lines each asynchronous log output dropped since
// start; an output that is not open reports 0.
func logCollector(file *platform.FileLog, sys *platform.Syslog) metrics.Collector {
	return func(e *metrics.Emitter) {
		var f, s uint64
		if file != nil {
			f = file.DroppedTotal()
		}
		if sys != nil {
			s = sys.DroppedTotal()
		}
		const help = "Log lines dropped because the output queue was full or the output failed."
		e.Counter("netshunt_log_dropped_lines_total", help, float64(f), metrics.L("output", "file")...)
		e.Counter("netshunt_log_dropped_lines_total", help, float64(s), metrics.L("output", "syslog")...)
	}
}

// registerMetrics adds the daemon-side collectors to the web server's
// registry.
func (d *Daemon) registerMetrics(reg *metrics.Registry) {
	reg.Register(d.Reconciler.Collect)
	reg.Register(netfilterCollector(d.Reconciler.IPSet, d.Conntrack))
	reg.Register(logCollector(d.FileLog, d.Syslog))
}
