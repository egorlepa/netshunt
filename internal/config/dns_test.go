package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestEffectiveUpstreamsDefaults(t *testing.T) {
	if got := (DNSConfig{}).EffectiveUpstreams(); !reflect.DeepEqual(got, DefaultDNSUpstreams()) {
		t.Errorf("empty upstreams = %v, want defaults", got)
	}
	custom := []DNSUpstream{{URL: "https://1.0.0.1/dns-query", SNI: "one.one.one.one"}}
	if got := (DNSConfig{Upstreams: custom}).EffectiveUpstreams(); !reflect.DeepEqual(got, custom) {
		t.Errorf("custom upstreams = %v, want %v", got, custom)
	}
	if err := ValidateUpstreams(DefaultDNSUpstreams()); err != nil {
		t.Errorf("defaults do not validate: %v", err)
	}
}

func TestUpstreamValidate(t *testing.T) {
	tests := []struct {
		name    string
		up      DNSUpstream
		wantErr string
	}{
		{"ok v4", DNSUpstream{"https://8.8.8.8/dns-query", "dns.google"}, ""},
		{"ok port", DNSUpstream{"https://8.8.8.8:443/dns-query", "dns.google"}, ""},
		{"ok v6", DNSUpstream{"https://[2001:4860:4860::8888]/dns-query", "dns.google"}, ""},
		{"http scheme", DNSUpstream{"http://8.8.8.8/dns-query", "dns.google"}, "scheme must be https"},
		{"hostname", DNSUpstream{"https://dns.google/dns-query", "dns.google"}, "must be an IP address"},
		{"empty sni", DNSUpstream{"https://8.8.8.8/dns-query", " "}, "sni is empty"},
		{"bad sni", DNSUpstream{"https://8.8.8.8/dns-query", "dns.google:443"}, "invalid sni"},
		{"garbage", DNSUpstream{"://", "x"}, "upstream"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.up.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseDNSUpstreams(t *testing.T) {
	got, err := ParseDNSUpstreams("\n  https://8.8.8.8/dns-query   dns.google \n\nhttps://1.1.1.1/dns-query cloudflare-dns.com\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []DNSUpstream{
		{URL: "https://8.8.8.8/dns-query", SNI: "dns.google"},
		{URL: "https://1.1.1.1/dns-query", SNI: "cloudflare-dns.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if FormatDNSUpstreams(got) != "https://8.8.8.8/dns-query dns.google\nhttps://1.1.1.1/dns-query cloudflare-dns.com" {
		t.Errorf("FormatDNSUpstreams round trip = %q", FormatDNSUpstreams(got))
	}

	if got, err := ParseDNSUpstreams("  \n "); err != nil || got != nil {
		t.Errorf("blank text = %v, %v; want nil, nil", got, err)
	}
	for _, bad := range []string{
		"https://8.8.8.8/dns-query",
		"https://8.8.8.8/dns-query dns.google extra",
		"https://dns.google/dns-query dns.google",
	} {
		if _, err := ParseDNSUpstreams(bad); err == nil {
			t.Errorf("ParseDNSUpstreams(%q) = nil error", bad)
		}
	}
}

func TestParseOldConfigWithDNSCrypt(t *testing.T) {
	old := `version: 1
routing:
    local_port: 1081
dns:
    listen_addr: :53
dnscrypt:
    port: 9153
ipset:
    table_name: bypass
`
	cfg, err := parse([]byte(old))
	if err != nil {
		t.Fatalf("old config with dnscrypt section failed to load: %v", err)
	}
	if cfg.Routing.LocalPort != 1081 || cfg.DNS.ListenAddr != ":53" || cfg.IPSet.TableName != "bypass" {
		t.Errorf("fields not loaded: %+v", cfg)
	}
	if !reflect.DeepEqual(cfg.DNS.EffectiveUpstreams(), DefaultDNSUpstreams()) {
		t.Errorf("upstreams = %v, want defaults", cfg.DNS.EffectiveUpstreams())
	}
}

func TestParseUpstreamsYAML(t *testing.T) {
	cfg, err := parse([]byte(`dns:
    listen_addr: :53
    upstreams:
        - url: https://9.9.9.9/dns-query
          sni: dns.quad9.net
`))
	if err != nil {
		t.Fatal(err)
	}
	want := []DNSUpstream{{URL: "https://9.9.9.9/dns-query", SNI: "dns.quad9.net"}}
	if !reflect.DeepEqual(cfg.DNS.Upstreams, want) {
		t.Errorf("upstreams = %v, want %v", cfg.DNS.Upstreams, want)
	}
}
