package shunt_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/egorlepa/netshunt/internal/shunt"
)

func TestValidate(t *testing.T) {
	good := []string{
		"example.com",
		"Example.COM",
		"https://www.example.com/path?q=1",
		"http://example.com:8080",
		"example.com.",
		"_dmarc.example.com",
		"xn--80ak6aa92e.com",
		"domain:example.com",
		"full:www.example.com",
		"keyword:tube",
		"keyword:Tube",
		`regexp:^www\.example\.net$`,
		`regexp:^.+\.google\.`,
		"1.2.3.4",
		"10.0.0.0/8",
		"1.2.3.4/32",
	}
	for _, v := range good {
		if err := shunt.Validate(v); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", v, err)
		}
	}

	bad := map[string]string{
		"":                               "empty",
		"   ":                            "empty",
		"regexp:(":                       "regexp",
		"regexp:":                        "empty regexp",
		`regexp:(?<=a)b`:                 "regexp", // lookbehind: not RE2
		"2001:db8::1":                    "IPv6",
		"2001:db8::/32":                  "IPv6",
		"::1":                            "IPv6",
		"bad domain":                     "not allowed",
		"exa$mple.com":                   "not allowed",
		"full:":                          "empty domain",
		"domain:":                        "empty domain",
		"keyword:":                       "empty keyword",
		"keyword:a b":                    "not allowed",
		"a..b.com":                       "empty label",
		".example.com":                   "empty label",
		"*.example.com":                  "not allowed",
		"full:exa mple.com":              "not allowed",
		"fulll:example.com":              "not allowed",
		"[2001:db8::1]":                  "not allowed",
		strings.Repeat("a", 64) + ".com": "63",
	}
	for v, want := range bad {
		err := shunt.Validate(v)
		var ie *shunt.InvalidEntryError
		if !errors.As(err, &ie) {
			t.Errorf("Validate(%q) = %v, want *InvalidEntryError", v, err)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Validate(%q) = %q, want it to mention %q", v, err, want)
		}
	}
}

func TestAddEntryRejectsInvalid(t *testing.T) {
	s := tempStore(t)
	_ = s.Create(shunt.Shunt{Name: "T", Enabled: true})
	for _, v := range []string{"regexp:(", "2001:db8::1", "2001:db8::/32", "bad domain", ""} {
		if err := s.AddEntry("T", v); err == nil {
			t.Errorf("AddEntry(%q) accepted", v)
		}
	}
	sh, _ := s.Get("T")
	if len(sh.Entries) != 0 {
		t.Fatalf("entries stored: %+v", sh.Entries)
	}
	if err := s.AddEntry("T", "HTTPS://Example.com/x"); err != nil {
		t.Fatal(err)
	}
	sh, _ = s.Get("T")
	if sh.Entries[0].Value != "example.com" {
		t.Fatalf("stored %q", sh.Entries[0].Value)
	}
}

func TestAddEntriesMixed(t *testing.T) {
	s := tempStore(t)
	_ = s.Create(shunt.Shunt{Name: "T", Enabled: true, Entries: []shunt.Entry{{Value: "dup.com"}}})
	res, err := s.AddEntries("T", []string{"a.com", "", "  ", "regexp:(", "1.2.3.4", "2001:db8::1", "keyword:x", "dup.com"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 3 || res.Duplicates != 1 || len(res.Rejected) != 2 {
		t.Fatalf("result = %+v", res)
	}
	if res.Rejected[0].Value != "regexp:(" || res.Rejected[1].Value != "2001:db8::1" {
		t.Fatalf("rejected = %v, %v", res.Rejected[0], res.Rejected[1])
	}
	sh, _ := s.Get("T")
	if len(sh.Entries) != 4 {
		t.Fatalf("entries = %+v", sh.Entries)
	}
	if _, err := s.AddEntries("missing", []string{"a.com"}); err == nil {
		t.Fatal("unknown shunt accepted")
	}
}

func TestImportRejectsInvalidEntry(t *testing.T) {
	s := tempStore(t)
	_ = s.Create(shunt.Shunt{Name: "Keep", Enabled: true})
	data := []byte("shunts:\n  - name: X\n    enabled: true\n    entries:\n      - value: ok.com\n      - value: \"regexp:(\"\n")
	err := s.ImportShunts(data)
	if err == nil || !strings.Contains(err.Error(), `"regexp:("`) || !strings.Contains(err.Error(), "X") {
		t.Fatalf("ImportShunts = %v", err)
	}
	shunts, _ := s.List()
	if len(shunts) != 1 || shunts[0].Name != "Keep" {
		t.Fatalf("store changed: %+v", shunts)
	}

	data = []byte("shunts:\n  - name: X\n    enabled: true\n    entries:\n      - value: OK.com\n")
	if err := s.ImportShunts(data); err != nil {
		t.Fatal(err)
	}
	sh, _ := s.Get("X")
	if sh.Entries[0].Value != "ok.com" {
		t.Fatalf("imported %q, want normalised", sh.Entries[0].Value)
	}
}

func TestEnabledEntriesCarryShuntName(t *testing.T) {
	s := tempStore(t)
	_ = s.Create(shunt.Shunt{Name: "A", Enabled: true, Entries: []shunt.Entry{{Value: "a.com"}}})
	entries, _ := s.EnabledEntries()
	if entries[0].Shunt != "A" {
		t.Fatalf("Shunt = %q", entries[0].Shunt)
	}
}
