package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// collectStream runs the streaming parser over input and copies each emitted
// domain into a freshly-allocated string slice for assertion convenience.
// Production callers never build such a slice — they insert directly into
// the matcher map — but tests need a stable value to compare.
func collectStream(t *testing.T, input string, format Format) []string {
	t.Helper()
	var out []string
	err := streamReader(strings.NewReader(input), format, func(b []byte) {
		out = append(out, string(b))
	})
	if err != nil {
		t.Fatalf("streamReader: %v", err)
	}
	return out
}

func TestStreamDomains(t *testing.T) {
	input := `# Hagezi-style list
! comment
; also comment

ads.example.com
Tracker.Net
*.wildcard.io
bad.invalid
foo.bar.co   # inline comment
localhost-missing-dot
bad$chars.com
`
	got := collectStream(t, input, FormatDomains)
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

func TestStreamHosts(t *testing.T) {
	input := `# hosts-file format
127.0.0.1 localhost
127.0.0.1 localhost.localdomain
255.255.255.255 broadcasthost
::1 localhost

# Custom host mappings — should be skipped (not 0.0.0.0/127.0.0.1)
10.0.0.5 internal.example

0.0.0.0 ads.example.com
0.0.0.0 Tracker.Net  # inline
127.0.0.1 malware.test
`
	got := collectStream(t, input, FormatHosts)
	want := []string{
		"ads.example.com",
		"tracker.net",
		"malware.test",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNormalizeBytes(t *testing.T) {
	cases := map[string]string{
		"Example.COM":     "example.com",
		"trailing.dot.":   "trailing.dot",
		"":                "",
		"no-tld":          "",
		"has space.com":   "",
		"evil$char.net":   "",
		"under_score.io":  "under_score.io",
		"MixedCase.Co.Uk": "mixedcase.co.uk",
	}
	for in, want := range cases {
		got := normalizeBytes([]byte(in))
		if string(got) != want {
			t.Errorf("normalizeBytes(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPresetByID(t *testing.T) {
	if p := PresetByID("hagezi-light"); p == nil || p.Format != FormatDomains || !p.DefaultOn {
		t.Errorf("PresetByID(hagezi-light) mismatch: %+v", p)
	}
	if p := PresetByID("hagezi-pro"); p == nil || p.Format != FormatDomains || p.DefaultOn {
		t.Errorf("PresetByID(hagezi-pro) mismatch: %+v", p)
	}
	if p := PresetByID("does-not-exist"); p != nil {
		t.Errorf("PresetByID(does-not-exist) = %+v, want nil", p)
	}
}

func TestDownloadRecordsValidators(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc123"`)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
		_, _ = w.Write([]byte("ads.example.com\n"))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "test.txt")
	res, err := Download(context.Background(), Source{URL: srv.URL, Format: FormatDomains}, dest, "", "")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if res.NotModified {
		t.Fatalf("expected fresh fetch, got NotModified")
	}
	if res.ETag != `"abc123"` {
		t.Errorf("ETag = %q, want %q", res.ETag, `"abc123"`)
	}
	if res.LastModified != "Wed, 21 Oct 2026 07:28:00 GMT" {
		t.Errorf("LastModified = %q", res.LastModified)
	}
	data, err := os.ReadFile(dest)
	if err != nil || !strings.Contains(string(data), "ads.example.com") {
		t.Errorf("dest content mismatch: %q err=%v", data, err)
	}
}

func TestDownloadConditional304(t *testing.T) {
	var gotIfNoneMatch, gotIfModSince string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIfNoneMatch = r.Header.Get("If-None-Match")
		gotIfModSince = r.Header.Get("If-Modified-Since")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "test.txt")
	// Seed dest with a prior body; Download must leave it alone on 304.
	if err := os.WriteFile(dest, []byte("stale.example.com\n"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	res, err := Download(context.Background(), Source{URL: srv.URL, Format: FormatDomains}, dest, `"abc123"`, "Wed, 21 Oct 2026 07:28:00 GMT")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if !res.NotModified {
		t.Errorf("NotModified = false, want true")
	}
	if gotIfNoneMatch != `"abc123"` {
		t.Errorf("server saw If-None-Match=%q, want %q", gotIfNoneMatch, `"abc123"`)
	}
	if gotIfModSince != "Wed, 21 Oct 2026 07:28:00 GMT" {
		t.Errorf("server saw If-Modified-Since=%q", gotIfModSince)
	}
	// Previous validators should be preserved on the result.
	if res.ETag != `"abc123"` {
		t.Errorf("ETag = %q, want carried-through previous value", res.ETag)
	}
	// Cache file must be untouched.
	data, _ := os.ReadFile(dest)
	if string(data) != "stale.example.com\n" {
		t.Errorf("cache modified on 304: %q", data)
	}
}

func TestDownloadExceedsSizeCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Stream one byte past the cap.
		buf := make([]byte, 1024*1024)
		total := 0
		for total <= MaxDownloadBytes {
			n, _ := w.Write(buf)
			total += n
		}
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "test.txt")
	_, err := Download(context.Background(), Source{URL: srv.URL, Format: FormatDomains}, dest, "", "")
	if err == nil {
		t.Fatalf("expected size-cap error, got nil")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Errorf("error %q, want one mentioning cap", err)
	}
	// dest must not exist — failed download should not leave a partial file.
	if _, statErr := os.Stat(dest); statErr == nil {
		t.Errorf("dest should not exist after cap failure")
	}
}

func TestStoreRecordUnknownID(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(filepath.Join(dir, "meta.yaml"), filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.RecordFetch("nope", 0, "", ""); err == nil {
		t.Errorf("RecordFetch on unknown id returned nil error")
	}
	if err := s.RecordUnchanged("nope"); err == nil {
		t.Errorf("RecordUnchanged on unknown id returned nil error")
	}
	if err := s.RecordError("nope", "boom"); err == nil {
		t.Errorf("RecordError on unknown id returned nil error")
	}
}

func TestStoreRecordFetchPersistsValidators(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meta.yaml")
	s, err := NewStore(path, filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.RecordFetch("hagezi-pro", 42, `"v1"`, "Wed, 21 Oct 2026 07:28:00 GMT"); err != nil {
		t.Fatalf("RecordFetch: %v", err)
	}
	st, ok := s.State("hagezi-pro")
	if !ok {
		t.Fatalf("hagezi-pro not found after RecordFetch")
	}
	if st.DomainCount != 42 || st.ETag != `"v1"` || st.LastModified == "" {
		t.Errorf("state not persisted: %+v", st)
	}

	// Reload from disk — validators must round-trip.
	s2, err := NewStore(path, filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	st2, _ := s2.State("hagezi-pro")
	if st2.ETag != `"v1"` || st2.LastModified != "Wed, 21 Oct 2026 07:28:00 GMT" {
		t.Errorf("validators did not round-trip: %+v", st2)
	}
}
