package healthcheck

import (
	"context"
	"testing"
	"time"
)

func TestRunAllKeepsOrderAndMeasures(t *testing.T) {
	checks := []Check{
		{Name: "slow", Run: func(context.Context) Result {
			time.Sleep(20 * time.Millisecond)
			return Result{Name: "slow", Passed: true}
		}},
		{Name: "fast", Run: func(context.Context) Result { return Result{Name: "fast"} }},
	}
	start := time.Now()
	res := RunAll(context.Background(), checks)
	if len(res) != 2 || res[0].Name != "slow" || res[1].Name != "fast" {
		t.Fatalf("results: %+v", res)
	}
	if res[0].Duration < 20*time.Millisecond || res[1].Duration > res[0].Duration {
		t.Errorf("durations: %v %v", res[0].Duration, res[1].Duration)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Error("checks not run concurrently")
	}
}
