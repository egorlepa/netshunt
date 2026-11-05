package healthcheck

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/egorlepa/netshunt/internal/config"
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

// Exactly the proxy connectivity checks are marked, so the background run
// can leave them out.
func TestChecksMarkConnectivity(t *testing.T) {
	cfg := config.Defaults()
	n := 0
	for _, c := range Checks(&cfg, nil) {
		want := strings.Contains(c.Name, "connectivity")
		if c.Connectivity != want {
			t.Errorf("%s: Connectivity = %v", c.Name, c.Connectivity)
		}
		if want {
			n++
		}
	}
	if n == 0 {
		t.Fatal("no connectivity check")
	}
}
