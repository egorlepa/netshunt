// Package blocklist provides DNS-level ad/tracker/malware blocking sourced
// from curated remote lists. Sources are downloaded on demand (manual
// "Update" trigger, mirroring the geosite pattern) and cached on disk. The
// matcher is built by merging all enabled source caches and deduplicating.
package blocklist

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Format describes the on-the-wire format of a blocklist source.
type Format int

const (
	// FormatDomains: one bare domain per line. Comments start with '#' or '!'.
	FormatDomains Format = iota
	// FormatHosts: "/etc/hosts" style lines — "0.0.0.0 domain.tld" or
	// "127.0.0.1 domain.tld". Entries not pointing at 0.0.0.0 / 127.0.0.1 are
	// skipped to avoid capturing unrelated host mappings.
	FormatHosts
)

// Source is a remote blocklist definition (preset).
type Source struct {
	ID          string
	Name        string
	Description string
	URL         string
	Format      Format
	DefaultOn   bool
}

// Presets is the built-in list of supported blocklist sources.
// Adding a source = adding one entry here.
var Presets = []Source{
	{
		ID:          "oisd-big",
		Name:        "OISD Big",
		Description: "Aggregated ads/tracking/malware list. Balanced false-positive handling.",
		URL:         "https://big.oisd.nl/domainswild2",
		Format:      FormatDomains,
		DefaultOn:   true,
	},
	{
		ID:          "hagezi-tif",
		Name:        "Hagezi Threat Intelligence",
		Description: "Malware, phishing, scam domains. Pairs with a general ad list.",
		URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt",
		Format:      FormatDomains,
		DefaultOn:   false,
	},
	{
		ID:          "stevenblack",
		Name:        "StevenBlack Unified Hosts",
		Description: "Community-maintained hosts file (ads + malware).",
		URL:         "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		Format:      FormatHosts,
		DefaultOn:   false,
	},
}

// PresetByID returns the preset with the given id, or nil if not found.
func PresetByID(id string) *Source {
	for i := range Presets {
		if Presets[i].ID == id {
			return &Presets[i]
		}
	}
	return nil
}

// CachePath returns the on-disk cache path for a given source id.
func CachePath(dir, id string) string {
	return filepath.Join(dir, id+".txt")
}

// MaxDownloadBytes caps a single source download to guard against a
// misbehaving or malicious upstream streaming unbounded data.
const MaxDownloadBytes = 50 * 1024 * 1024

// DownloadResult reports the outcome of a Download call.
type DownloadResult struct {
	// NotModified is true when upstream returned 304; destPath is left untouched.
	NotModified bool
	// ETag and LastModified are the validators from the upstream response,
	// empty if not provided. On NotModified the caller should keep the
	// previously-stored values.
	ETag         string
	LastModified string
}

// Download fetches src into destPath atomically. If prevETag or prevLastModified
// are non-empty they are sent as If-None-Match / If-Modified-Since — on a 304
// response destPath is not touched and the returned DownloadResult has
// NotModified=true. The response body is capped at MaxDownloadBytes.
func Download(ctx context.Context, src Source, destPath, prevETag, prevLastModified string) (DownloadResult, error) {
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return DownloadResult{}, fmt.Errorf("create directory: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "netshunt/blocklist")
	if prevETag != "" {
		req.Header.Set("If-None-Match", prevETag)
	}
	if prevLastModified != "" {
		req.Header.Set("If-Modified-Since", prevLastModified)
	}

	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		return DownloadResult{NotModified: true, ETag: prevETag, LastModified: prevLastModified}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return DownloadResult{}, fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(filepath.Dir(destPath), filepath.Base(destPath)+".*.tmp")
	if err != nil {
		return DownloadResult{}, fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	// Read one extra byte past the cap so we can distinguish "exactly at cap"
	// from "exceeded cap".
	limited := io.LimitReader(resp.Body, MaxDownloadBytes+1)
	written, err := io.Copy(tmp, limited)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("write: %w", err)
	}
	if written > MaxDownloadBytes {
		return DownloadResult{}, fmt.Errorf("download exceeds %d byte cap", MaxDownloadBytes)
	}
	if err := tmp.Close(); err != nil {
		return DownloadResult{}, fmt.Errorf("close: %w", err)
	}

	if err := os.Rename(tmpName, destPath); err != nil {
		return DownloadResult{}, fmt.Errorf("rename: %w", err)
	}
	return DownloadResult{
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}, nil
}

// Parse reads a cache file and returns the domains it contains.
// The returned domains are lowercased, have no comment lines, no empty lines,
// and no format-specific sigils. Duplicates within the same file are removed.
func Parse(path string, format Format) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return parseReader(f, format)
}

func parseReader(r io.Reader, format Format) ([]string, error) {
	seen := make(map[string]struct{})
	var domains []string

	scanner := bufio.NewScanner(r)
	// Allow long lines (some adguard-style lines can be long).
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		d := extract(scanner.Text(), format)
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		domains = append(domains, d)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}

// extract returns a single normalized domain from a line, or "" if the line
// should be skipped (comment, blank, unsupported content).
func extract(line string, format Format) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	// Common comment markers.
	if line[0] == '#' || line[0] == '!' || line[0] == ';' {
		return ""
	}

	switch format {
	case FormatDomains:
		// Strip inline comment.
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		// Some "domains" lists ship with a leading wildcard sigil ("*.example.com").
		line = strings.TrimPrefix(line, "*.")
		return normalizeDomain(line)

	case FormatHosts:
		// "0.0.0.0 ads.example.com  # comment"
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return ""
		}
		ip := fields[0]
		if ip != "0.0.0.0" && ip != "127.0.0.1" && ip != "::" && ip != "::1" {
			return ""
		}
		host := fields[1]
		// Skip localhost-ish entries present in standard hosts file.
		if isLocalhostName(host) {
			return ""
		}
		return normalizeDomain(host)
	}
	return ""
}

func normalizeDomain(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	s = strings.ToLower(s)
	if s == "" {
		return ""
	}
	// Sanity check — must contain at least one dot and only valid DNS chars.
	if !strings.ContainsRune(s, '.') {
		return ""
	}
	for _, r := range s {
		if r == '.' || r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			continue
		}
		return ""
	}
	return s
}

func isLocalhostName(h string) bool {
	switch strings.ToLower(h) {
	case "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
		"ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes",
		"ip6-allrouters", "ip6-allhosts":
		return true
	}
	return false
}
