package dns_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/egorlepa/netshunt/internal/dns"
	"github.com/egorlepa/netshunt/internal/shunt"
)

func TestGenerateIPSetConfig(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "dnsmasq.d", "netshunt.dnsmasq")

	d := &dns.DnsmasqConfig{
		IPSetTable: "unblock",
		OutputFile: outFile,
	}

	entries := []shunt.Entry{
		{Value: "youtube.com"},
		{Value: "googlevideo.com"},
		{Value: "10.0.0.0/8"},       // CIDR — should be skipped
		{Value: "1.2.3.4"},           // IP — should be skipped
		{Value: "instagram.com"},
	}

	changed, err := d.GenerateIPSetConfig(entries)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected changed=true on first write")
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}

	expected := "ipset=/youtube.com/unblock\nipset=/googlevideo.com/unblock\nipset=/instagram.com/unblock\n"
	if string(data) != expected {
		t.Fatalf("unexpected output:\ngot:  %q\nwant: %q", string(data), expected)
	}

	// Second call — no change.
	changed, err = d.GenerateIPSetConfig(entries)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("expected changed=false when content is identical")
	}
}

func TestGenerateIPSetConfigEmpty(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "dnsmasq.d", "netshunt.dnsmasq")

	d := &dns.DnsmasqConfig{
		IPSetTable: "unblock",
		OutputFile: outFile,
	}

	changed, err := d.GenerateIPSetConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected changed=true on first write")
	}

	data, _ := os.ReadFile(outFile)
	if string(data) != "" {
		t.Fatalf("expected empty file, got: %q", string(data))
	}
}
