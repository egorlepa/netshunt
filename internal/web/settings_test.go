package web

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/dns"
)

func formRequest(t *testing.T, method string, values url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, "/settings", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestSettingsFromFormUpstreams(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		want    []config.DNSUpstream
		wantErr string
	}{
		{"empty means defaults", "  \r\n", nil, ""},
		{"two lines", "https://8.8.8.8/dns-query dns.google\r\n\r\n https://1.1.1.1/dns-query  cloudflare-dns.com \r\n",
			[]config.DNSUpstream{
				{URL: "https://8.8.8.8/dns-query", SNI: "dns.google"},
				{URL: "https://1.1.1.1/dns-query", SNI: "cloudflare-dns.com"},
			}, ""},
		{"missing sni", "https://8.8.8.8/dns-query", nil, "invalid DNS upstreams"},
		{"hostname", "https://dns.google/dns-query dns.google", nil, "must be an IP address"},
		{"plain http", "http://8.8.8.8/dns-query dns.google", nil, "scheme must be https"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.DNS.Upstreams = []config.DNSUpstream{{URL: "https://9.9.9.9/dns-query", SNI: "dns.quad9.net"}}
			err := settingsFromForm(&cfg, formRequest(t, http.MethodPut, url.Values{"dns_upstreams": {tt.text}}))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cfg.DNS.Upstreams, tt.want) {
				t.Errorf("upstreams = %v, want %v", cfg.DNS.Upstreams, tt.want)
			}
		})
	}
}

func newSettingsTestServer(t *testing.T) *Server {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	fwd, err := dns.NewForwarder(":0", dns.ConfigUpstreams(config.DNSConfig{}), nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	return NewServer(config.NewLive(&cfg), nil, nil, nil, fwd, nil, nil, nil, logger, "test")
}

// An invalid upstream is rejected with an error toast before anything is
// saved or applied.
func TestUpdateSettingsRejectsInvalidUpstreams(t *testing.T) {
	s := newSettingsTestServer(t)
	before := s.Forwarder.UpstreamStats()

	req := httptest.NewRequest(http.MethodPut, "/settings",
		strings.NewReader(url.Values{"dns_upstreams": {"https://dns.google/dns-query dns.google"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if trig := rec.Header().Get("HX-Trigger"); !strings.Contains(trig, "invalid DNS upstreams") || !strings.Contains(trig, `"error"`) {
		t.Errorf("HX-Trigger = %q, want an error toast", trig)
	}
	if after := s.Forwarder.UpstreamStats(); !reflect.DeepEqual(after, before) {
		t.Errorf("forwarder upstreams changed on a rejected save")
	}
}

func TestSettingsUpstreamsApplyLive(t *testing.T) {
	s := newSettingsTestServer(t)
	cfg := config.Defaults()
	if err := settingsFromForm(&cfg, formRequest(t, http.MethodPut, url.Values{
		"dns_upstreams": {"https://1.0.0.1/dns-query one.one.one.one"},
	})); err != nil {
		t.Fatal(err)
	}
	if err := s.applyDNSUpstreams(&cfg); err != nil {
		t.Fatal(err)
	}
	got := s.Forwarder.UpstreamStats()
	if len(got) != 1 || got[0].Upstream.SNI != "one.one.one.one" {
		t.Errorf("upstreams after swap = %+v", got)
	}

	// Clearing the textarea goes back to the defaults.
	cfg.DNS.Upstreams = nil
	if err := s.applyDNSUpstreams(&cfg); err != nil {
		t.Fatal(err)
	}
	if got := s.Forwarder.UpstreamStats(); len(got) != 3 {
		t.Errorf("upstreams after clearing = %d, want the 3 defaults", len(got))
	}
}

func TestSettingsSyslogToggle(t *testing.T) {
	for _, tt := range []struct {
		name string
		vals []string
		from bool
		want bool
	}{
		{"checked", []string{"0", "1"}, false, true},
		{"unchecked", []string{"0"}, true, false},
		{"field absent keeps value", nil, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Daemon.Syslog = tt.from
			form := url.Values{}
			if tt.vals != nil {
				form["syslog"] = tt.vals
			}
			if err := settingsFromForm(&cfg, formRequest(t, http.MethodPut, form)); err != nil {
				t.Fatal(err)
			}
			if cfg.Daemon.Syslog != tt.want {
				t.Errorf("syslog = %v, want %v", cfg.Daemon.Syslog, tt.want)
			}
		})
	}
}
