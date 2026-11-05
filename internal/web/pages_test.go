package web

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/egorlepa/netshunt/internal/blocklist"
	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/dns"
	"github.com/egorlepa/netshunt/internal/healthcheck"
	"github.com/egorlepa/netshunt/internal/platform"
	"github.com/egorlepa/netshunt/internal/shunt"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

type fakeTracker struct {
	members, domains, ips int
}

func (f *fakeTracker) Count() (int, int) { return f.domains, f.ips }
func (f *fakeTracker) Members() int      { return f.members }

type fakeLogs struct{ entries []platform.LogEntry }

func (f fakeLogs) Entries() []platform.LogEntry { return f.entries }

func newPagesTestServer(t *testing.T) (*Server, *fakeTracker) {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	store := shunt.NewStore(filepath.Join(t.TempDir(), "shunts.yaml"))
	if err := store.Create(shunt.Shunt{Name: "Video", Enabled: true, Entries: []shunt.Entry{{Value: "youtube.com"}, {Value: "1.2.3.4"}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(shunt.Shunt{Name: "Off", Entries: []shunt.Entry{{Value: "off.example"}}}); err != nil {
		t.Fatal(err)
	}
	fwd, err := dns.NewForwarder(":0", dns.ConfigUpstreams(config.DNSConfig{}), nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	tr := &fakeTracker{members: 941, domains: 266, ips: 582}
	cfg := config.Defaults()
	logs := fakeLogs{entries: []platform.LogEntry{
		{Time: time.Now(), Level: "WARN", Msg: "all dns upstreams failed", KV: []platform.LogAttr{{Key: "name", Value: "x.com"}, {Key: "errors", Value: `"timeout"`}}},
		{Time: time.Now(), Level: "INFO", Msg: "reconcile complete"},
	}}
	s := NewServer(config.NewLive(&cfg), store, nil, &fakeGeosite{}, fwd, &countingReconciler{}, tr, logs, logger, "1.5.7~rc33")
	s.ksDrops.read = func(context.Context) (uint64, error) { return 1234, nil }
	return s, tr
}

func TestActivityEndpoint(t *testing.T) {
	s, _ := newPagesTestServer(t)
	a := s.Forwarder.Activity()
	a.Record("192.168.1.21", "www.youtube.com", "www.youtube.com", dns.MatchInfo{Shunt: "Video", Kind: dns.MatchSuffix, Rule: "youtube.com"})
	a.Record("10.7.1.3", "i.ytimg.com", "i.ytimg.com", dns.MatchInfo{Shunt: "Video", Kind: dns.MatchExact, Rule: "i.ytimg.com"})

	get := func(path string) activityResponse {
		t.Helper()
		rec := do(t, s, http.MethodGet, path)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Header().Get("Content-Type"))
		}
		var v activityResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	v := get("/api/activity")
	if v.Seq != 2 || v.Held != 2 || len(v.Entries) != 2 || v.Entries[0].Name != "i.ytimg.com" || v.Entries[1].Dim != len("www.") {
		t.Fatalf("activity: %+v", v)
	}
	if len(v.Shunts) != 1 || v.Shunts[0].Name != "Video" || v.Shunts[0].N != 2 || len(v.Clients) != 2 {
		t.Errorf("hour: %+v %+v", v.Shunts, v.Clients)
	}
	if st := v.Stats; st.IPs != 941 || st.Domains != 266 || st.Shunts != 1 || st.Entries != 2 || st.KSDrops != 1234 {
		t.Errorf("stats: %+v", v.Stats)
	}
	if v := get("/api/activity?since=2"); len(v.Entries) != 0 || v.Seq != 2 {
		t.Errorf("since=2: %+v", v)
	}
	// A sequence from before a daemon restart starts over.
	if v := get("/api/activity?since=99"); len(v.Entries) != 2 || v.Seq != 2 {
		t.Errorf("since=99: %+v", v)
	}
	// Top lists are capped.
	for i := range 12 {
		a.Record("10.0.0."+string(rune('a'+i)), "x", "x", dns.MatchInfo{Shunt: "S" + string(rune('a'+i))})
	}
	if v := get("/api/activity?since=2"); len(v.Shunts) != topShunts || len(v.Clients) != topClients || len(v.Entries) != 12 {
		t.Errorf("caps: %d shunts %d clients %d entries", len(v.Shunts), len(v.Clients), len(v.Entries))
	}
	// Empty lists are arrays, not null, for the page script.
	empty := NewServer(s.Config, s.Shunts, nil, nil, nil, nil, nil, nil, s.Logger, "x")
	empty.ksDrops.read = func(context.Context) (uint64, error) { return 0, nil }
	rec := do(t, empty, http.MethodGet, "/api/activity")
	if !strings.Contains(rec.Body.String(), `"entries":[]`) || !strings.Contains(rec.Body.String(), `"shunts":[]`) {
		t.Errorf("no forwarder: %s", rec.Body.String())
	}
}

func TestKillSwitchCounterIsCached(t *testing.T) {
	var reads atomic.Int32
	k := &ksCounter{read: func(context.Context) (uint64, error) { return uint64(reads.Add(1)), nil }}
	first := k.get(context.Background())
	second := k.get(context.Background())
	if first != 1 || second != 1 || reads.Load() != 1 {
		t.Fatalf("not cached: reads %d", reads.Load())
	}
	k.at = time.Now().Add(-ksDropsTTL)
	if k.get(context.Background()) != 2 {
		t.Error("not refreshed after the TTL")
	}
}

func TestHealthRunnerCoalesces(t *testing.T) {
	var runs atomic.Int32
	release := make(chan struct{})
	h := newHealthRunner(func() []healthcheck.Check {
		runs.Add(1)
		return []healthcheck.Check{{Name: "a", Run: func(context.Context) healthcheck.Result {
			<-release
			return healthcheck.Result{Name: "a", Passed: true}
		}}}
	})
	var wg sync.WaitGroup
	results := make([][]healthcheck.Result, 5)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], _, _ = h.BaseResults(context.Background())
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	if runs.Load() != 1 {
		t.Fatalf("concurrent callers ran %d times", runs.Load())
	}
	for _, r := range results {
		if len(r) != 1 || !r[0].Passed {
			t.Fatalf("results: %+v", r)
		}
	}
	// Fresh result reused; stale one re-run.
	_, _, _ = h.BaseResults(context.Background())
	if runs.Load() != 1 {
		t.Error("fresh result not reused")
	}
	h.base.mu.Lock()
	h.base.lastAt = time.Now().Add(-healthFresh)
	h.base.mu.Unlock()
	_, _, _ = h.BaseResults(context.Background())
	if runs.Load() != 2 {
		t.Error("stale result not re-run")
	}
	// A caller that gives up does not cancel the run for the others.
	h.base.mu.Lock()
	h.base.lastAt = time.Time{}
	h.base.mu.Unlock()
	block := make(chan struct{})
	h.checks = func() []healthcheck.Check {
		return []healthcheck.Check{{Name: "b", Run: func(context.Context) healthcheck.Result { <-block; return healthcheck.Result{Name: "b"} }}}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := h.BaseResults(ctx); err == nil {
		t.Error("cancelled wait returned no error")
	}
	close(block)
	res, _, err := h.BaseResults(context.Background())
	if err != nil || len(res) != 1 || res[0].Name != "b" {
		t.Errorf("after cancel: %+v %v", res, err)
	}
}

func TestDashboardHealthHero(t *testing.T) {
	s, _ := newPagesTestServer(t)
	s.health.checks = func() []healthcheck.Check {
		return []healthcheck.Check{
			{Name: "ok", Run: func(context.Context) healthcheck.Result { return healthcheck.Result{Name: "ok", Passed: true} }},
			{Name: "proxy connectivity", Run: func(context.Context) healthcheck.Result {
				return healthcheck.Result{Name: "proxy connectivity", Detail: "0/5 reachable via proxy"}
			}},
			{Name: "blocklist", Run: func(context.Context) healthcheck.Result {
				return healthcheck.Result{Name: "blocklist", Warn: true, Detail: "stale."}
			}},
		}
	}
	body := do(t, s, http.MethodGet, "/dashboard/health").Body.String()
	for _, want := range []string{`class="hero bad"`, `class="dot bad"`, "1 check failing", "<b>proxy connectivity</b>: 0/5 reachable via proxy.", "<b>blocklist</b>: stale.", `href="/diagnostics"`} {
		if !strings.Contains(body, want) {
			t.Errorf("hero lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<b>ok</b>") {
		t.Error("passing check listed")
	}

	s.health = newHealthRunner(func() []healthcheck.Check {
		return []healthcheck.Check{{Name: "ok", Run: func(context.Context) healthcheck.Result { return healthcheck.Result{Name: "ok", Passed: true} }}}
	})
	body = do(t, s, http.MethodGet, "/dashboard/health").Body.String()
	if !strings.Contains(body, `class="dot on"`) || !strings.Contains(body, "All checks passing") || strings.Contains(body, `class="sub"`) {
		t.Errorf("passing hero:\n%s", body)
	}
}

func TestDashboardPage(t *testing.T) {
	s, _ := newPagesTestServer(t)
	body := do(t, s, http.MethodGet, "/").Body.String()
	for _, want := range []string{
		`id="live" checked autocomplete="off"`,
		`hx-get="/dashboard/health"`,
		`<b data-k="ips">941</b> IPs in set`,
		`<b data-k="ks_drops">1<i class="k"></i>234</b> kill switch drops`,
		`<b data-k="shunts">1</b> shunts, <b data-k="entries">2</b> entries`,
		`<script src="/static/dashboard.js">`,
		`<span class="ver">v1.5.7~rc33</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard lacks %s", want)
		}
	}
	for _, gone := range []string{"switch-proxy", "Active proxy", "Refresh", "Overview"} {
		if strings.Contains(body, gone) {
			t.Errorf("dashboard still has %s", gone)
		}
	}
	if rec := do(t, s, http.MethodPost, "/actions/switch-proxy"); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("switch-proxy still routed: %d", rec.Code)
	}
}

func TestBlocklistCheckEndpoint(t *testing.T) {
	s, _ := newPagesTestServer(t)
	s.Forwarder.Blocklist().Replace(func(add func([]byte)) { add([]byte("doubleclick.net")) })
	check := func(domain string) (int, string) {
		rec := do(t, s, http.MethodGet, "/blocklist/check?domain="+domain)
		return rec.Code, rec.Body.String()
	}
	cfg := s.Config.Load()
	cfg.Blocklist.Enabled = true
	code, body := check("https://Stats.G.DoubleClick.net./path")
	if code != http.StatusOK || !strings.Contains(body, "Blocked:") || !strings.Contains(body, "<b>stats.g.doubleclick.net</b> by suffix <b>doubleclick.net</b>") {
		t.Errorf("blocked: %d %s", code, body)
	}
	if _, body := check("example.com"); !strings.Contains(body, "Not blocked:") {
		t.Errorf("not blocked: %s", body)
	}
	cfg.Blocklist.Enabled = false
	if _, body := check("ad.doubleclick.net"); !strings.Contains(body, "DNS blocking is off") {
		t.Errorf("disabled: %s", body)
	}
	if code, _ := check("%20"); code != http.StatusBadRequest {
		t.Errorf("empty: %d", code)
	}
}

func TestNormalizeCheckDomain(t *testing.T) {
	for in, want := range map[string]string{
		"Ads.Example.COM.":                       "ads.example.com",
		" https://user@ads.example.com:8443/x?y": "ads.example.com",
		"ads.example.com/path":                   "ads.example.com",
		"":                                       "",
	} {
		if got := normalizeCheckDomain(in); got != want {
			t.Errorf("normalizeCheckDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBlocklistPageStrip(t *testing.T) {
	s, _ := newPagesTestServer(t)
	store, err := newTestBlocklistStore(t)
	if err != nil {
		t.Fatal(err)
	}
	s.Blocklist = store
	s.Forwarder.Blocklist().Replace(func(add func([]byte)) { add([]byte("a.com")); add([]byte("b.com")) })
	body := do(t, s, http.MethodGet, "/blocklist").Body.String()
	for _, want := range []string{"<b>2</b> domains loaded", `data-fmt="time"`, "matcher <b>", `hx-get="/blocklist/check"`, "daily 03:00, next in ", `class="head b-head"`, "Test a domain"} {
		if !strings.Contains(body, want) {
			t.Errorf("blocklist page lacks %s", want)
		}
	}
}

func TestExportConfig(t *testing.T) {
	s, _ := newPagesTestServer(t)
	s.configFile = filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(s.configFile, []byte("version: 1\nrouting:\n  local_port: 1081\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := do(t, s, http.MethodGet, "/settings/export")
	if rec.Code != http.StatusOK || rec.Body.String() != "version: 1\nrouting:\n  local_port: 1081\n" ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("export: %d %q %q", rec.Code, rec.Body.String(), rec.Header().Get("Content-Disposition"))
	}
	s.configFile = filepath.Join(t.TempDir(), "missing.yaml")
	if rec := do(t, s, http.MethodGet, "/settings/export"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "local_port: 1080") {
		t.Errorf("fallback: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSettingsFormKeepsBackupPort(t *testing.T) {
	cfg := config.Defaults()
	cfg.Routing.BackupPort, cfg.Routing.UseBackup = 1082, true
	if err := settingsFromForm(&cfg, formRequest(t, http.MethodPut, map[string][]string{"routing_local_port": {"1081"}})); err != nil {
		t.Fatal(err)
	}
	if cfg.Routing.LocalPort != 1081 || cfg.Routing.BackupPort != 1082 || !cfg.Routing.UseBackup {
		t.Errorf("routing after save: %+v", cfg.Routing)
	}
}

func TestDiagnosticsPageAndLogs(t *testing.T) {
	s, _ := newPagesTestServer(t)
	body := do(t, s, http.MethodGet, "/diagnostics").Body.String()
	for _, want := range []string{"Force reconcile", `id="runchk"`, `id="d-pass"`, `class="head d-head"`, `class="dot spin"`, "checking", `id="lq"`, `data-l="WARN"`, `id="lwrap"`} {
		if !strings.Contains(body, want) {
			t.Errorf("diagnostics lacks %s", want)
		}
	}
	body = do(t, s, http.MethodGet, "/diagnostics/logs").Body.String()
	for _, want := range []string{
		`class="ll WARN" data-l="WARN"`,
		`data-s="all dns upstreams failed name=x.com errors=&#34;timeout&#34;"`,
		`<em>name=</em><span class="v">x.com</span>`,
		`<span class="m" title="reconcile complete">reconcile complete</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("logs lack %s:\n%s", want, body)
		}
	}
}

// Every page renders, and every server-rendered checkbox opts out of
// form-state restoration.
func TestPagesRenderWithAutocompleteOff(t *testing.T) {
	s, _ := newPagesTestServer(t)
	store, err := newTestBlocklistStore(t)
	if err != nil {
		t.Fatal(err)
	}
	s.Blocklist = store
	cb := regexp.MustCompile(`<input[^>]*type="checkbox"[^>]*>`)
	for _, path := range []string{"/", "/shunts", "/geosite", "/blocklist", "/diagnostics", "/settings"} {
		rec := do(t, s, http.MethodGet, path)
		if path == "/settings" && rec.Code == http.StatusInternalServerError {
			continue // reads /opt/etc/netshunt/config.yaml; covered by renderSettings below
		}
		if rec.Code != http.StatusOK {
			t.Errorf("%s: %d", path, rec.Code)
			continue
		}
		for _, m := range cb.FindAllString(rec.Body.String(), -1) {
			if !strings.Contains(m, `autocomplete="off"`) {
				t.Errorf("%s: checkbox without autocomplete=off: %s", path, m)
			}
		}
		if strings.ContainsAny(rec.Body.String(), "\u2013\u2014") {
			t.Errorf("%s: en or em dash in the page", path)
		}
	}
}

func newTestBlocklistStore(t *testing.T) (*blocklist.Store, error) {
	t.Helper()
	dir := t.TempDir()
	return blocklist.NewStore(filepath.Join(dir, "blocklist.yaml"), filepath.Join(dir, "cache"))
}

func TestSettingsPageRender(t *testing.T) {
	cfg := config.Defaults()
	cfg.Routing.BackupPort = 1082
	cfg.Network.AdditionalInterfaces = []string{"awg0"}
	var b strings.Builder
	if err := templates.SettingsPage(&cfg).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	body := b.String()
	for _, want := range []string{
		"<h2>Routing</h2>", "<h2>DNS</h2>", "<h2>Network</h2>", "<h2>Daemon</h2>", "<h2>Maintenance</h2>",
		`name="routing_local_port" value="1080"`, `>awg0</textarea>`, "Using defaults: dns.google",
		`href="/settings/export"`, `href="/shunts/export"`, `href="/shunts?import=1"`,
		`id="savebar"`, "Save and apply", "Discard",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("settings lack %s", want)
		}
	}
	for _, gone := range []string{"backup", "Backup", "Restart daemon", "confirm("} {
		if strings.Contains(body, gone) {
			t.Errorf("settings still have %q", gone)
		}
	}
}
