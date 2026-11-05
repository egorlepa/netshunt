// Package metrics is a minimal Prometheus text exposition (format 0.0.4)
// without dependencies: atomic counters and a fixed-bucket histogram for
// event counts that exist nowhere else, and collectors that read the
// daemon's existing state at scrape time.
package metrics

import (
	"bufio"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// ContentType is the Content-Type of the text exposition format.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Metric types, as written on the # TYPE line.
const (
	TypeCounter   = "counter"
	TypeGauge     = "gauge"
	TypeHistogram = "histogram"
)

// Counter is a monotonically increasing count. The zero value is ready.
type Counter struct{ v atomic.Uint64 }

// Inc adds one.
func (c *Counter) Inc() { c.v.Add(1) }

// Add adds n.
func (c *Counter) Add(n uint64) { c.v.Add(n) }

// Load returns the current count.
func (c *Counter) Load() uint64 { return c.v.Load() }

// Gauge is a float value that can go up and down. The zero value is ready.
type Gauge struct{ bits atomic.Uint64 }

// Set stores v.
func (g *Gauge) Set(v float64) { g.bits.Store(math.Float64bits(v)) }

// Load returns the current value.
func (g *Gauge) Load() float64 { return math.Float64frombits(g.bits.Load()) }

// Histogram counts observations in fixed buckets. Observe takes no lock and
// allocates nothing.
type Histogram struct {
	bounds  []float64       // upper bounds, ascending, without +Inf
	counts  []atomic.Uint64 // per bucket, not cumulative; last is +Inf
	sumBits atomic.Uint64
	count   atomic.Uint64
}

// NewHistogram returns a histogram with the given ascending upper bounds
// (the +Inf bucket is implicit).
func NewHistogram(bounds ...float64) *Histogram {
	b := slices.Clone(bounds)
	slices.Sort(b)
	return &Histogram{bounds: b, counts: make([]atomic.Uint64, len(b)+1)}
}

// Observe records v.
func (h *Histogram) Observe(v float64) {
	i := 0
	for i < len(h.bounds) && v > h.bounds[i] {
		i++
	}
	h.counts[i].Add(1)
	for {
		old := h.sumBits.Load()
		if h.sumBits.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+v)) {
			break
		}
	}
	h.count.Add(1)
}

// HistogramSnapshot is a point-in-time copy of a histogram: Cumulative[i]
// counts observations <= Bounds[i], the last element is the +Inf bucket.
type HistogramSnapshot struct {
	Bounds     []float64
	Cumulative []uint64
	Sum        float64
	Count      uint64
}

// Snapshot copies the histogram. Concurrent observations may land between
// the reads; the +Inf bucket is reported equal to Count so the exposition
// stays consistent.
func (h *Histogram) Snapshot() HistogramSnapshot {
	s := HistogramSnapshot{Bounds: h.bounds, Cumulative: make([]uint64, len(h.counts))}
	var acc uint64
	for i := range h.counts {
		acc += h.counts[i].Load()
		s.Cumulative[i] = acc
	}
	s.Count = h.count.Load()
	s.Sum = math.Float64frombits(h.sumBits.Load())
	last := len(s.Cumulative) - 1
	if s.Count < s.Cumulative[last] {
		s.Count = s.Cumulative[last]
	}
	s.Cumulative[last] = s.Count
	return s
}

// Label is one name="value" pair.
type Label struct{ Name, Value string }

// L builds labels from name, value pairs. An odd trailing name is dropped.
func L(kv ...string) []Label {
	out := make([]Label, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, Label{kv[i], kv[i+1]})
	}
	return out
}

type sample struct {
	suffix string // "", "_bucket", "_sum", "_count"
	labels []Label
	value  float64
}

type family struct {
	name, help, typ string
	samples         []sample
}

// Emitter collects the samples of one scrape. Collectors add samples to
// it; families with the same name are merged.
type Emitter struct {
	families map[string]*family
}

func (e *Emitter) family(name, help, typ string) *family {
	f := e.families[name]
	if f == nil {
		f = &family{name: name, help: help, typ: typ}
		e.families[name] = f
	}
	return f
}

// Declare makes the family appear (HELP and TYPE) even when no sample is
// added to it in this scrape.
func (e *Emitter) Declare(name, help, typ string) { e.family(name, help, typ) }

// Counter adds a counter sample.
func (e *Emitter) Counter(name, help string, v float64, labels ...Label) {
	f := e.family(name, help, TypeCounter)
	f.samples = append(f.samples, sample{labels: labels, value: v})
}

// Gauge adds a gauge sample.
func (e *Emitter) Gauge(name, help string, v float64, labels ...Label) {
	f := e.family(name, help, TypeGauge)
	f.samples = append(f.samples, sample{labels: labels, value: v})
}

// Histogram adds the samples of a histogram snapshot.
func (e *Emitter) Histogram(name, help string, s HistogramSnapshot, labels ...Label) {
	f := e.family(name, help, TypeHistogram)
	for i, c := range s.Cumulative {
		le := "+Inf"
		if i < len(s.Bounds) {
			le = formatFloat(s.Bounds[i])
		}
		f.samples = append(f.samples, sample{suffix: "_bucket", labels: append(slices.Clip(labels), Label{"le", le}), value: float64(c)})
	}
	f.samples = append(f.samples,
		sample{suffix: "_sum", labels: labels, value: s.Sum},
		sample{suffix: "_count", labels: labels, value: float64(s.Count)})
}

// Collector adds samples to e at scrape time. It must not block on slow
// operations.
type Collector func(e *Emitter)

// Registry holds the collectors of one endpoint.
type Registry struct {
	mu         sync.Mutex
	collectors []Collector
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds a collector.
func (r *Registry) Register(c Collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectors = append(r.collectors, c)
}

// WriteTo runs every collector and writes the exposition: families sorted by
// name, samples of counters and gauges sorted by labels, histogram samples
// in bucket order.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	collectors := slices.Clone(r.collectors)
	r.mu.Unlock()

	e := &Emitter{families: map[string]*family{}}
	for _, c := range collectors {
		c(e)
	}
	names := make([]string, 0, len(e.families))
	for n := range e.families {
		names = append(names, n)
	}
	slices.Sort(names)

	cw := &countingWriter{w: w}
	bw := bufio.NewWriter(cw)
	var line []byte
	for _, n := range names {
		f := e.families[n]
		_, _ = bw.WriteString("# HELP " + f.name + " " + escapeHelp(f.help) + "\n")
		_, _ = bw.WriteString("# TYPE " + f.name + " " + f.typ + "\n")
		if f.typ != TypeHistogram {
			slices.SortStableFunc(f.samples, func(a, b sample) int {
				return strings.Compare(labelKey(a.labels), labelKey(b.labels))
			})
		}
		for _, s := range f.samples {
			line = appendSample(line[:0], f.name, s)
			_, _ = bw.Write(line) // a write error sticks; Flush returns it
		}
	}
	err := bw.Flush()
	return cw.n, err
}

// Handler serves the registry.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ContentType)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = r.WriteTo(w)
	})
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func labelKey(ls []Label) string {
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.Name)
		b.WriteByte(0)
		b.WriteString(l.Value)
		b.WriteByte(0)
	}
	return b.String()
}

func appendSample(b []byte, name string, s sample) []byte {
	b = append(b, name...)
	b = append(b, s.suffix...)
	if len(s.labels) > 0 {
		b = append(b, '{')
		for i, l := range s.labels {
			if i > 0 {
				b = append(b, ',')
			}
			b = append(b, l.Name...)
			b = append(b, '=', '"')
			b = appendEscapedLabel(b, l.Value)
			b = append(b, '"')
		}
		b = append(b, '}')
	}
	b = append(b, ' ')
	b = append(b, formatFloat(s.value)...)
	return append(b, '\n')
}

// appendEscapedLabel escapes backslash, double quote and newline.
func appendEscapedLabel(b []byte, v string) []byte {
	for i := 0; i < len(v); i++ {
		switch c := v[i]; c {
		case '\\':
			b = append(b, '\\', '\\')
		case '"':
			b = append(b, '\\', '"')
		case '\n':
			b = append(b, '\\', 'n')
		default:
			b = append(b, c)
		}
	}
	return b
}

// escapeHelp escapes backslash and newline.
func escapeHelp(s string) string {
	if !strings.ContainsAny(s, "\\\n") {
		return s
	}
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}
