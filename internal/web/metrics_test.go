package web

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/egorlepa/netshunt/internal/healthcheck"
)

// healthFixture installs three checks on s: a passing one, a warning one and
// a connectivity check that counts its runs.
func healthFixture(s *Server) (base, conn *atomic.Int32) {
	base, conn = &atomic.Int32{}, &atomic.Int32{}
	s.health = newHealthRunner(func() []healthcheck.Check {
		return []healthcheck.Check{
			{Name: "ok", Run: func(context.Context) healthcheck.Result {
				base.Add(1)
				return healthcheck.Result{Name: "ok", Passed: true}
			}},
			{Name: "proxy primary connectivity (active)", Connectivity: true, Run: func(context.Context) healthcheck.Result {
				conn.Add(1)
				return healthcheck.Result{Name: "proxy primary connectivity (active)", Detail: "0/5 reachable via proxy"}
			}},
			{Name: "blocklist", Run: func(context.Context) healthcheck.Result {
				return healthcheck.Result{Name: "blocklist", Passed: true, Warn: true, Detail: "stale."}
			}},
		}
	})
	return base, conn
}

// The background run never executes the connectivity checks; the metric
// reports its results; the dashboard then runs only connectivity on demand
// and shows every check.
func TestBackgroundHealthExcludesConnectivity(t *testing.T) {
	s, _ := newPagesTestServer(t)
	base, conn := healthFixture(s)

	ctx, cancel := context.WithCancel(context.Background())
	s.StartBackgroundHealth(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if res, _ := s.health.LastBase(); res != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background run did not finish")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if conn.Load() != 0 {
		t.Fatalf("background run executed connectivity %d times", conn.Load())
	}
	res, _ := s.health.LastBase()
	if len(res) != 2 || res[0].Name != "ok" || res[1].Name != "blocklist" {
		t.Fatalf("base results: %+v", res)
	}

	body := do(t, s, http.MethodGet, "/metrics").Body.String()
	for _, want := range []string{`netshunt_healthcheck_ok{check="ok"} 1`, `netshunt_healthcheck_ok{check="blocklist"} 0`} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	if strings.Contains(body, "connectivity (active)\"}") {
		t.Error("connectivity check exposed")
	}

	// Dashboard: base is fresh from the background, connectivity runs now.
	hero := do(t, s, http.MethodGet, "/dashboard/health").Body.String()
	if base.Load() != 1 || conn.Load() != 1 {
		t.Fatalf("dashboard runs: base %d, connectivity %d; want 1, 1", base.Load(), conn.Load())
	}
	if !strings.Contains(hero, "1 check failing") || !strings.Contains(hero, "<b>proxy primary connectivity (active)</b>") {
		t.Errorf("hero:\n%s", hero)
	}
	all, _, err := s.health.Results(context.Background())
	if err != nil || len(all) != 3 || all[1].Name != "proxy primary connectivity (active)" {
		t.Errorf("merged results not in check order: %+v %v", all, err)
	}
	if conn.Load() != 1 {
		t.Error("fresh connectivity result not reused")
	}
	// Metrics still report the background set only.
	body = do(t, s, http.MethodGet, "/metrics").Body.String()
	if strings.Contains(body, "connectivity (active)\"}") {
		t.Error("connectivity check exposed after a dashboard run")
	}
}

func TestMetricsEndpointWebFamilies(t *testing.T) {
	s, _ := newPagesTestServer(t)
	rec := do(t, s, http.MethodGet, "/metrics")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("GET /metrics: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	for _, want := range []string{
		`netshunt_dns_queries_total{result="cache_hit"} 0`,
		`netshunt_dns_upstream_duration_seconds_bucket{le="+Inf"} 0`,
		`netshunt_dns_upstream_requests_total{upstream="`,
		"netshunt_ipset_members 941",
		"netshunt_tracked_domains 266",
		"netshunt_shunts_enabled 1",
		"netshunt_shunt_entries 2",
		"netshunt_killswitch_drops_total 1234",
		`netshunt_update_failures_total{job="geosite"} 0`,
		`netshunt_update_last_success_timestamp_seconds{job="blocklist"} 0`,
		`netshunt_build_info{version="1.5.7~rc33"} 1`,
		"# TYPE netshunt_healthcheck_ok gauge",
		"# TYPE netshunt_killswitch_drops_total counter",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
}
