package metrics

import (
	"runtime"
	"runtime/metrics"
	"time"
)

// startTime approximates the process start: package initialisation.
var startTime = time.Now()

// Heap in use = live and dead objects plus unused spans that are not yet
// returned to the OS; the same quantity as runtime.MemStats.HeapInuse,
// read without stopping the world.
var heapInuseSamples = []string{
	"/memory/classes/heap/objects:bytes",
	"/memory/classes/heap/unused:bytes",
}

// ProcessCollector reports a small fixed set of process metrics: goroutines,
// heap in use, start time and the build version. Not the full default
// go_*/process_* sets.
func ProcessCollector(version string) Collector {
	return func(e *Emitter) {
		e.Gauge("go_goroutines", "Number of goroutines that currently exist.", float64(runtime.NumGoroutine()))
		s := make([]metrics.Sample, len(heapInuseSamples))
		for i, n := range heapInuseSamples {
			s[i].Name = n
		}
		metrics.Read(s)
		var heap uint64
		for _, x := range s {
			if x.Value.Kind() == metrics.KindUint64 {
				heap += x.Value.Uint64()
			}
		}
		e.Gauge("go_memstats_heap_inuse_bytes", "Number of heap bytes that are in use.", float64(heap))
		e.Gauge("process_start_time_seconds", "Start time of the process since unix epoch in seconds.", float64(startTime.UnixNano())/1e9)
		e.Gauge("netshunt_build_info", "Build information; the value is always 1.", 1, Label{"version", version})
	}
}
