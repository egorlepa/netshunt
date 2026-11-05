package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func render(t *testing.T, r *Registry) string {
	t.Helper()
	var b strings.Builder
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestExpositionFormat(t *testing.T) {
	r := NewRegistry()
	var c Counter
	c.Add(3)
	r.Register(func(e *Emitter) {
		e.Gauge("b_gauge", "A gauge\\with a\nnewline.", 1.5, L("x", `q"uo\te`+"\n")...)
		e.Counter("a_total", "Events.", float64(c.Load()), L("k", "z")...)
		e.Counter("a_total", "Events.", 7, L("k", "a")...)
		e.Declare("c_empty", "Nothing yet.", TypeGauge)
	})
	got := render(t, r)
	want := `# HELP a_total Events.
# TYPE a_total counter
a_total{k="a"} 7
a_total{k="z"} 3
# HELP b_gauge A gauge\\with a\nnewline.
# TYPE b_gauge gauge
b_gauge{x="q\"uo\\te\n"} 1.5
# HELP c_empty Nothing yet.
# TYPE c_empty gauge
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestHistogram(t *testing.T) {
	h := NewHistogram(0.1, 0.5, 1)
	for _, v := range []float64{0.05, 0.1, 0.3, 0.7, 2, 5} {
		h.Observe(v)
	}
	r := NewRegistry()
	r.Register(func(e *Emitter) { e.Histogram("d_seconds", "Durations.", h.Snapshot()) })
	got := render(t, r)
	want := `# HELP d_seconds Durations.
# TYPE d_seconds histogram
d_seconds_bucket{le="0.1"} 2
d_seconds_bucket{le="0.5"} 3
d_seconds_bucket{le="1"} 4
d_seconds_bucket{le="+Inf"} 6
d_seconds_sum 8.15
d_seconds_count 6
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestHistogramConcurrent(t *testing.T) {
	h := NewHistogram(1)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				h.Observe(0.5)
				_ = h.Snapshot()
			}
		}()
	}
	wg.Wait()
	s := h.Snapshot()
	if s.Count != 8000 || s.Cumulative[0] != 8000 || s.Cumulative[1] != 8000 || s.Sum != 4000 {
		t.Fatalf("snapshot = %+v", s)
	}
}

func TestHandlerAndProcess(t *testing.T) {
	r := NewRegistry()
	r.Register(ProcessCollector("1.2.3"))
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("content type %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"go_goroutines ", "go_memstats_heap_inuse_bytes ", "process_start_time_seconds ", `netshunt_build_info{version="1.2.3"} 1`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in\n%s", want, body)
		}
	}
}
