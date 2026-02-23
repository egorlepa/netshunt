package dns

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/egorlepa/netshunt/internal/shunt"
	"github.com/egorlepa/netshunt/internal/platform"
)

// DnsmasqConfig generates and manages dnsmasq ipset configuration.
type DnsmasqConfig struct {
	IPSetTable string // ipset table name (e.g., "unblock")
	OutputFile string // path to generated config file
}

// NewDnsmasqConfig creates a DnsmasqConfig with defaults.
func NewDnsmasqConfig(ipsetTable string) *DnsmasqConfig {
	return &DnsmasqConfig{
		IPSetTable: ipsetTable,
		OutputFile: platform.DnsmasqIPSetFile,
	}
}

// GenerateIPSetConfig generates the dnsmasq ipset config file from the given entries.
// Only domain entries produce ipset directives; IP/CIDR entries are skipped
// (they go directly into ipset via the reconciler).
//
// For each domain entry "example.com", generates:
//
//	ipset=/example.com/unblock
//
// This makes dnsmasq automatically add resolved IPs to the ipset table
// when any client queries the domain (including all subdomains).
func (d *DnsmasqConfig) GenerateIPSetConfig(entries []shunt.Entry) (bool, error) {
	var lines []string
	for _, e := range entries {
		if !e.IsDomain() {
			continue
		}
		domain := strings.TrimSpace(strings.ToLower(e.Value))
		lines = append(lines, fmt.Sprintf("ipset=/%s/%s", domain, d.IPSetTable))
	}

	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}

	// Check if content has changed.
	existing, err := os.ReadFile(d.OutputFile)
	if err == nil && string(existing) == content {
		return false, nil
	}

	if err := os.MkdirAll(filepath.Dir(d.OutputFile), 0755); err != nil {
		return false, fmt.Errorf("create dnsmasq.d dir: %w", err)
	}

	if err := os.WriteFile(d.OutputFile, []byte(content), 0644); err != nil {
		return false, fmt.Errorf("write dnsmasq ipset config: %w", err)
	}

	return true, nil
}

// RemoveIPSetConfig removes the generated config file.
func (d *DnsmasqConfig) RemoveIPSetConfig() error {
	if err := os.Remove(d.OutputFile); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
