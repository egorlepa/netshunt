package dns

import (
	"bufio"
	"os"
	"runtime"
	"strings"
	"testing"
)

const hageziPath = "testdata/hagezi-pro.txt"

// loadBlocklistDomains reads the Hagezi Pro list one domain per line.
// Skipped if the file is missing (large; not committed).
func loadBlocklistDomains(tb testing.TB) []string {
	tb.Helper()
	f, err := os.Open(hageziPath)
	if err != nil {
		tb.Skipf(`blocklist not found at %s; download with:
  mkdir -p internal/dns/testdata && \
    curl -sSL -o internal/dns/testdata/hagezi-pro.txt \
      https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt`, hageziPath)
	}
	defer func() { _ = f.Close() }()

	domains := make([]string, 0, 500_000)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		domains = append(domains, strings.ToLower(line))
	}
	if err := sc.Err(); err != nil {
		tb.Fatalf("scan: %v", err)
	}
	return domains
}

// measureRetained returns heap delta from a clean baseline to after `build`
// completes and all transient state is freed. Only what `build` returns
// (and what it references) is retained.
func measureRetained(t *testing.T, build func() any) (retained uint64, totalAfter uint64) {
	t.Helper()
	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	kept := build()

	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	runtime.KeepAlive(kept)
	return after.HeapAlloc - before.HeapAlloc, after.HeapAlloc
}

// pickSample returns up to n evenly-spaced elements from src for stable
// benchmarks across runs.
func pickSample(src []string, n int) []string {
	if len(src) <= n {
		return src
	}
	step := len(src) / n
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, src[i*step])
	}
	return out
}

// ──────────────────────────────────────────────────────────────────────────
// SuffixSet — production blocklist matcher.
// ──────────────────────────────────────────────────────────────────────────

func buildSuffixSet(domains []string) *SuffixSet {
	return BuildSuffixSet(func(add func(string)) {
		for _, d := range domains {
			add(d)
		}
	})
}

func TestSuffixSetMemoryFootprint(t *testing.T) {
	if _, err := os.Stat(hageziPath); err != nil {
		t.Skipf("blocklist not found at %s", hageziPath)
	}

	var n int
	retained, total := measureRetained(t, func() any {
		data, err := os.ReadFile(hageziPath)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var domains []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line[0] == '#' {
				continue
			}
			domains = append(domains, strings.ToLower(string([]byte(line))))
		}
		s := buildSuffixSet(domains)
		n = s.Len()
		return s
	})

	t.Logf("domains:             %d", n)
	t.Logf("retained by set:     %.2f MB (%.0f bytes/entry)",
		float64(retained)/1024/1024, float64(retained)/float64(n))
	t.Logf("heap total after:    %.2f MB", float64(total)/1024/1024)
}

func BenchmarkSuffixSetBuild(b *testing.B) {
	domains := loadBlocklistDomains(b)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := buildSuffixSet(domains)
		runtime.KeepAlive(s)
	}
}

func BenchmarkSuffixSetLookupHitExact(b *testing.B) {
	domains := loadBlocklistDomains(b)
	s := buildSuffixSet(domains)
	hits := pickSample(domains, 1024)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !s.Match(hits[i&1023]) {
			b.Fatalf("expected hit on %q", hits[i&1023])
		}
	}
}

func BenchmarkSuffixSetLookupHitSuffix(b *testing.B) {
	domains := loadBlocklistDomains(b)
	s := buildSuffixSet(domains)
	base := pickSample(domains, 1024)
	subs := make([]string, len(base))
	for i, d := range base {
		subs[i] = "x.y.z." + d
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !s.Match(subs[i&1023]) {
			b.Fatalf("expected suffix hit on %q", subs[i&1023])
		}
	}
}

func BenchmarkSuffixSetLookupMiss(b *testing.B) {
	domains := loadBlocklistDomains(b)
	s := buildSuffixSet(domains)
	misses := []string{
		"example.com", "anthropic.com", "claude.ai", "github.com",
		"wikipedia.org", "reddit.com", "news.ycombinator.com", "go.dev",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if s.Match(misses[i%len(misses)]) {
			b.Fatalf("expected miss on %q", misses[i%len(misses)])
		}
	}
}
