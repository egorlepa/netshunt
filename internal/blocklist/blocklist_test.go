package blocklist

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseDomains(t *testing.T) {
	input := `# OISD-style list
! comment
; also comment

ads.example.com
Tracker.Net
*.wildcard.io
bad.invalid
foo.bar.co   # inline comment
ads.example.com
localhost-missing-dot
bad$chars.com
`
	got, err := parseReader(strings.NewReader(input), FormatDomains)
	if err != nil {
		t.Fatalf("parseReader: %v", err)
	}
	want := []string{
		"ads.example.com",
		"tracker.net",
		"wildcard.io",
		"bad.invalid",
		"foo.bar.co",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseHosts(t *testing.T) {
	input := `# StevenBlack-style hosts file
127.0.0.1 localhost
127.0.0.1 localhost.localdomain
255.255.255.255 broadcasthost
::1 localhost

# Custom host mappings — should be skipped (not 0.0.0.0/127.0.0.1)
10.0.0.5 internal.example

0.0.0.0 ads.example.com
0.0.0.0 Tracker.Net  # inline
0.0.0.0 duplicate.test
0.0.0.0 duplicate.test
127.0.0.1 malware.test
`
	got, err := parseReader(strings.NewReader(input), FormatHosts)
	if err != nil {
		t.Fatalf("parseReader: %v", err)
	}
	want := []string{
		"ads.example.com",
		"tracker.net",
		"duplicate.test",
		"malware.test",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"Example.COM":      "example.com",
		"trailing.dot.":    "trailing.dot",
		"":                 "",
		"no-tld":           "",
		"has space.com":    "",
		"evil$char.net":    "",
		"  spaced.io  ":    "spaced.io",
		"under_score.io":   "under_score.io",
		"MixedCase.Co.Uk":  "mixedcase.co.uk",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPresetByID(t *testing.T) {
	if p := PresetByID("oisd-big"); p == nil || p.Format != FormatDomains {
		t.Errorf("PresetByID(oisd-big) mismatch: %+v", p)
	}
	if p := PresetByID("stevenblack"); p == nil || p.Format != FormatHosts {
		t.Errorf("PresetByID(stevenblack) mismatch: %+v", p)
	}
	if p := PresetByID("does-not-exist"); p != nil {
		t.Errorf("PresetByID(does-not-exist) = %+v, want nil", p)
	}
}
