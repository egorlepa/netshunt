// Package blocklist provides DNS-level ad/tracker/malware blocking sourced
// from curated remote lists. Sources are downloaded on demand (manual
// "Update" trigger, mirroring the geosite pattern) and cached on disk.
//
// The matcher is built by streaming each enabled source's cache file
// line-by-line directly into the matcher's rule set — no intermediate
// []string or []shunt.Entry slice is materialised. This matters on routers
// where a 1M-entry list would otherwise peak tens of MB of transient heap.
package blocklist

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
//
// Sizing target: routers have limited RAM. Light is the default; Pro is
// opt-in for users who have headroom.
var Presets = []Source{
	{
		ID:          "hagezi-light",
		Name:        "Hagezi Light",
		Description: "Router-friendly default: ads, tracking, telemetry, phishing. Low false-positive rate, ~130k entries.",
		URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt",
		Format:      FormatDomains,
		DefaultOn:   true,
	},
	{
		ID:          "hagezi-pro",
		Name:        "Hagezi Multi PRO",
		Description: "Heavier coverage: ads, tracking, telemetry, phishing, malware, scam, fake, cryptojacking. ~410k entries — needs RAM headroom.",
		URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
		Format:      FormatDomains,
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

// MaxDownloadBytes caps a single source download. The largest list we ship
// (Hagezi Pro) is ~10 MB; 15 MB is a real ceiling that flags misconfig early
// and keeps router RAM predictable.
const MaxDownloadBytes = 15 * 1024 * 1024

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
// NotModified=true. The response body is capped at MaxDownloadBytes and
// streamed directly to disk (never buffered entirely in memory).
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

// StreamFile opens path and invokes emit for every normalized domain in the
// file. emit receives a byte slice that is only valid until the next call;
// the caller must copy it (e.g. via string(b)) to retain it.
//
// This is the low-memory path: no []string is built, no dedup map is kept —
// dedup happens in whatever target data structure emit writes to.
func StreamFile(path string, format Format, emit func(domain []byte)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return streamReader(f, format, emit)
}

func streamReader(r io.Reader, format Format, emit func([]byte)) error {
	scanner := bufio.NewScanner(r)
	// 64 KB initial buffer, 256 KB line ceiling. Plain-domain lists never
	// need more; guards against pathological input.
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)

	for scanner.Scan() {
		d := extractAndNormalize(scanner.Bytes(), format)
		if len(d) == 0 {
			continue
		}
		emit(d)
	}
	return scanner.Err()
}

// extractAndNormalize reads one line of input and returns the normalized
// domain bytes (lowercased in place inside the scanner's buffer) or nil if
// the line is a comment / unsupported / invalid.
//
// Important: the returned slice aliases the scanner's buffer. It is only
// valid until the next call into the scanner — the emit callback must copy
// before retaining.
func extractAndNormalize(line []byte, format Format) []byte {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return nil
	}
	switch line[0] {
	case '#', '!', ';':
		return nil
	}

	switch format {
	case FormatDomains:
		if i := bytes.IndexByte(line, '#'); i >= 0 {
			line = bytes.TrimSpace(line[:i])
		}
		line = bytes.TrimPrefix(line, []byte("*."))
		return normalizeBytes(line)

	case FormatHosts:
		if i := bytes.IndexByte(line, '#'); i >= 0 {
			line = bytes.TrimSpace(line[:i])
		}
		// Fast two-field split — avoids strings.Fields allocation.
		idx := bytes.IndexAny(line, " \t")
		if idx < 0 {
			return nil
		}
		ip := line[:idx]
		if !isHostsSinkholeIP(ip) {
			return nil
		}
		rest := line[idx+1:]
		// Skip extra whitespace between IP and host.
		for len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
			rest = rest[1:]
		}
		hostEnd := bytes.IndexAny(rest, " \t")
		host := rest
		if hostEnd >= 0 {
			host = rest[:hostEnd]
		}
		if isLocalhostNameBytes(host) {
			return nil
		}
		return normalizeBytes(host)
	}
	return nil
}

// normalizeBytes lowercases (in place) and validates s. Returns s (possibly
// shortened) if valid, nil otherwise. Requires at least one '.' and DNS-safe
// ASCII only.
func normalizeBytes(s []byte) []byte {
	// Trim a single trailing dot (FQDN form).
	for len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	if len(s) == 0 {
		return nil
	}
	hasDot := false
	for i, b := range s {
		switch {
		case b >= 'A' && b <= 'Z':
			s[i] = b + ('a' - 'A')
		case b == '.':
			hasDot = true
		case b == '-', b == '_',
			b >= 'a' && b <= 'z',
			b >= '0' && b <= '9':
			// ok
		default:
			return nil
		}
	}
	if !hasDot {
		return nil
	}
	return s
}

func isHostsSinkholeIP(b []byte) bool {
	switch string(b) {
	case "0.0.0.0", "127.0.0.1", "::", "::1":
		return true
	}
	return false
}

func isLocalhostNameBytes(h []byte) bool {
	// Case-fold without allocating a string.
	if len(h) == 0 || len(h) > 32 {
		return false
	}
	var buf [32]byte
	for i, b := range h {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		buf[i] = b
	}
	switch string(buf[:len(h)]) {
	case "localhost", "localhost.localdomain", "local", "broadcasthost",
		"ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
		"ip6-allnodes", "ip6-allrouters", "ip6-allhosts":
		return true
	}
	return false
}
