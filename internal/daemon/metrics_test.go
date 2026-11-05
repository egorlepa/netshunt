package daemon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/egorlepa/netshunt/internal/metrics"
	"github.com/egorlepa/netshunt/internal/netfilter"
	"github.com/egorlepa/netshunt/internal/platform"
	"github.com/egorlepa/netshunt/internal/web"
)

func scrape(t *testing.T, reg *metrics.Registry) string {
	t.Helper()
	var b strings.Builder
	if _, err := reg.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func wantLines(t *testing.T, body string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !strings.Contains(body, l+"\n") {
			t.Errorf("missing %q in\n%s", l, body)
		}
	}
}

func TestReconcileMetricsOkAndError(t *testing.T) {
	h := newHarness(t)
	reg := metrics.NewRegistry()
	reg.Register(h.r.Collect)
	h.create("a", true, "198.51.100.7")
	// Kernel holds a member nothing explains; the static entry is missing.
	h.ipset.members["192.0.2.77"] = struct{}{}

	h.reconcile()
	h.mutate()
	body := scrape(t, reg)
	wantLines(t, body,
		`netshunt_reconcile_total{kind="full",result="ok"} 1`,
		`netshunt_reconcile_total{kind="full",result="error"} 0`,
		`netshunt_reconcile_total{kind="mutation",result="ok"} 1`,
		`netshunt_ipset_repair_added_total 1`,
		`netshunt_ipset_repair_removed_total 1`,
	)
	if h.r.stats.full.lastSuccess.Load() == 0 || h.r.stats.mutation.lastSuccess.Load() == 0 {
		t.Error("last success timestamps not set")
	}
	if strings.Contains(body, `netshunt_reconcile_last_success_timestamp_seconds{kind="full"} 0`+"\n") {
		t.Error("full last success exposed as 0")
	}

	// TPROXY cannot be installed: the full reconcile is an error, the last
	// success time stays.
	okAt := h.r.stats.full.lastSuccess.Load()
	h.mode.err = errors.New("udp tproxy: scripted")
	if err := h.r.Reconcile(context.Background()); err == nil {
		t.Fatal("no error")
	}
	// A mutation that fails (cancelled context) is a mutation error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.create("b", true, "example.org")
	h.resolve("www.example.org", "198.51.100.9")
	if err := h.r.ApplyMutation(ctx); err == nil {
		t.Fatal("cancelled mutation succeeded")
	}
	wantLines(t, scrape(t, reg),
		`netshunt_reconcile_total{kind="full",result="ok"} 1`,
		`netshunt_reconcile_total{kind="full",result="error"} 1`,
		`netshunt_reconcile_total{kind="mutation",result="error"} 1`,
	)
	if h.r.stats.full.lastSuccess.Load() != okAt {
		t.Error("failed reconcile moved the last success time")
	}
}

func TestBlocklistSourceDomainsMetric(t *testing.T) {
	h := newBlocklistHarness(t)
	reg := metrics.NewRegistry()
	reg.Register(h.r.Collect)
	h.writeCache("hagezi-light", "ads.example.com\nads.example.net\n", blMtime)
	h.apply()
	// hagezi-doh is enabled by default and has no file: 0.
	wantLines(t, scrape(t, reg),
		`netshunt_blocklist_source_domains{source="hagezi-light"} 2`,
		`netshunt_blocklist_source_domains{source="hagezi-doh"} 0`,
	)
	cfg := *h.r.Config.Load()
	cfg.Blocklist.Enabled = false
	h.r.Config.Store(&cfg)
	h.apply()
	if body := scrape(t, reg); strings.Contains(body, "netshunt_blocklist_source_domains{") {
		t.Errorf("disabled blocklist still reports sources:\n%s", body)
	}
}

// agreedMetrics is every metric family /metrics must expose.
var agreedMetrics = []string{
	"netshunt_dns_queries_total",
	"netshunt_dns_upstream_duration_seconds",
	"netshunt_dns_upstream_requests_total",
	"netshunt_dns_upstream_wins_total",
	"netshunt_dns_upstream_errors_total",
	"netshunt_ipset_members",
	"netshunt_tracked_domains",
	"netshunt_shunts_enabled",
	"netshunt_shunt_entries",
	"netshunt_killswitch_drops_total",
	"netshunt_reconcile_total",
	"netshunt_reconcile_last_duration_seconds",
	"netshunt_reconcile_last_success_timestamp_seconds",
	"netshunt_ipset_repair_added_total",
	"netshunt_ipset_repair_removed_total",
	"netshunt_netfilter_backend",
	"netshunt_blocklist_source_domains",
	"netshunt_update_last_success_timestamp_seconds",
	"netshunt_update_failures_total",
	"netshunt_log_dropped_lines_total",
	"go_goroutines",
	"go_memstats_heap_inuse_bytes",
	"process_start_time_seconds",
	"netshunt_build_info",
	"netshunt_healthcheck_ok",
}

// The daemon's wiring: the web server's /metrics with the daemon
// collectors registered serves every agreed family.
func TestMetricsEndpointEndToEnd(t *testing.T) {
	h := newBlocklistHarness(t)
	h.writeCache("hagezi-light", "ads.example.com\n", blMtime)
	h.create("a", true, "198.51.100.7")
	h.reconcile()

	fileLog, err := platform.OpenFileLog(t.TempDir() + "/netshunt.log")
	if err != nil {
		t.Fatal(err)
	}
	defer fileLog.Close()
	d := &Daemon{
		Config:     h.r.Config,
		Shunts:     h.store,
		Reconciler: h.r,
		Forwarder:  h.fwd,
		Conntrack:  &netfilter.Conntrack{Runner: h.run},
		FileLog:    fileLog,
	}
	srv := web.NewServer(h.r.Config, h.store, h.bl, nil, h.fwd, h.r, h.fwd.TrackerRef(), nil, h.r.Logger, "1.5.7~rc40")
	d.registerMetrics(srv.Metrics())

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("content type %q", ct)
	}
	body := rec.Body.String()
	for _, name := range agreedMetrics {
		if !strings.Contains(body, "# TYPE "+name+" ") {
			t.Errorf("family %s missing", name)
		}
	}
	wantLines(t, body,
		`netshunt_netfilter_backend{component="conntrack",backend="exec"} 1`,
		`netshunt_netfilter_backend{component="ipset",backend="netlink"} 0`,
		`netshunt_log_dropped_lines_total{output="file"} 0`,
		`netshunt_log_dropped_lines_total{output="syslog"} 0`,
		`netshunt_reconcile_total{kind="full",result="ok"} 1`,
		`netshunt_shunts_enabled 1`,
		`netshunt_ipset_members 1`,
		`netshunt_build_info{version="1.5.7~rc40"} 1`,
	)
	series := 0
	for l := range strings.Lines(body) {
		if !strings.HasPrefix(l, "#") {
			series++
		}
	}
	if series > 300 {
		t.Errorf("%d series, budget 300", series)
	}
}
