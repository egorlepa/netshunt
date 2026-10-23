package dns

import (
	"fmt"
	"runtime"
	"testing"
)

// syntheticBlocklist returns n distinct lowercase domains of mixed depth, as
// the byte slices the blocklist stream hands to the build callback.
func syntheticBlocklist(n int) [][]byte {
	out := make([][]byte, 0, n)
	tlds := []string{"com", "net", "org", "io", "co.uk", "ru"}
	for i := range n {
		var d string
		switch i % 3 {
		case 0:
			d = fmt.Sprintf("ads%d.example%d.%s", i, i%997, tlds[i%len(tlds)])
		case 1:
			d = fmt.Sprintf("tracker-%d.%s", i, tlds[i%len(tlds)])
		default:
			d = fmt.Sprintf("a.b%d.telemetry%d.cdn.%s", i, i%31, tlds[i%len(tlds)])
		}
		out = append(out, []byte(d))
	}
	return out
}

// BenchmarkBuildSuffixSet measures the blocklist rebuild as the reconciler
// drives it: one callback per streamed domain byte slice.
func BenchmarkBuildSuffixSet(b *testing.B) {
	domains := syntheticBlocklist(200_000)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		s := BuildSuffixSet(func(add func([]byte)) {
			for _, d := range domains {
				add(d)
			}
		})
		runtime.KeepAlive(s)
	}
}

func TestReverseLabelsBytesMatchesString(t *testing.T) {
	for _, d := range []string{"com", "example.com", "foo.bar.example.co.uk", "a.b"} {
		got := string(reverseLabelsAppendBytes(nil, []byte(d)))
		want := string(reverseLabelsAppend(nil, d))
		if got != want {
			t.Errorf("%q: bytes %q, string %q", d, got, want)
		}
	}
}

func TestBuildSuffixSetCopiesReusedBuffer(t *testing.T) {
	// The stream hands out one buffer rewritten per line: the set must keep
	// its own copy of every domain.
	buf := make([]byte, 0, 64)
	s := BuildSuffixSet(func(add func([]byte)) {
		for _, d := range []string{"ads.example.org", "tracker.net", "ads.example.org", ""} {
			buf = append(buf[:0], d...)
			add(buf)
		}
	})
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}
	for q, want := range map[string]bool{
		"ads.example.org": true, "x.ads.example.org": true, "tracker.net": true,
		"example.org": false, "nottracker.net": false,
	} {
		if got := s.Match(q); got != want {
			t.Errorf("Match(%q) = %v, want %v", q, got, want)
		}
	}
	if n := testing.AllocsPerRun(100, func() { s.Match("a.b.c.ads.example.org") }); n != 0 {
		t.Errorf("Match allocates %v times", n)
	}
}

func TestSuffixSetMatchSuffixAndSize(t *testing.T) {
	s := BuildSuffixSet(func(add func([]byte)) {
		for _, d := range []string{"doubleclick.net", "ads.example.com", "example.com", "tracker.io"} {
			add([]byte(d))
		}
	})
	tests := []struct {
		q, want string
		ok      bool
	}{
		{"stats.g.doubleclick.net", "doubleclick.net", true},
		{"doubleclick.net", "doubleclick.net", true},
		{"x.ads.example.com", "example.com", true}, // shortest stored suffix
		{"notdoubleclick.net", "", false},
		{"io", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := s.MatchSuffix(tt.q)
		if got != tt.want || ok != tt.ok {
			t.Errorf("MatchSuffix(%q) = %q %v, want %q %v", tt.q, got, ok, tt.want, tt.ok)
		}
		if s.Match(tt.q) != tt.ok {
			t.Errorf("Match(%q) disagrees", tt.q)
		}
	}
	// data: the reversed entries with their dots; offsets: 5 uint32.
	if got, want := s.SizeBytes(), len("doubleclick.net.ads.example.com.example.com.tracker.io.")+4*5; got != want {
		t.Errorf("SizeBytes = %d, want %d", got, want)
	}
	if (&SuffixSet{}).SizeBytes() != 0 {
		t.Error("empty set has a size")
	}

	m := NewBlocklistMatcher()
	if !m.BuiltAt().IsZero() {
		t.Error("BuiltAt before any build")
	}
	m.Replace(func(add func([]byte)) { add([]byte("doubleclick.net")) })
	if sfx, ok := m.MatchSuffix("ad.doubleclick.net"); !ok || sfx != "doubleclick.net" || m.BuiltAt().IsZero() || m.SizeBytes() == 0 {
		t.Errorf("matcher: %q %v built=%v size=%d", sfx, ok, m.BuiltAt(), m.SizeBytes())
	}
}
