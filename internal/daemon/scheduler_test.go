package daemon

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/egorlepa/netshunt/internal/config"
)

type nopJobs struct{}

func (nopJobs) UpdateAllBlocklistSources(context.Context) (int, int) { return 0, 0 }
func (nopJobs) UpdateGeosite(context.Context) (int, error)           { return 0, nil }

// A settings save replaces the config while cron ticks read it; run with
// -race to catch a regression to in-place config writes.
func TestSchedulerConfigSwapRace(t *testing.T) {
	cfg := config.Defaults()
	live := config.NewLive(&cfg)
	s := NewScheduler(live, nopJobs{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 200 {
			cfg := config.Defaults()
			cfg.Blocklist.AutoUpdate.Enabled = i%2 == 0
			cfg.Geosite.AutoUpdate.Enabled = i%2 == 1
			live.Store(&cfg)
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			s.runBlocklist()
			s.runGeosite()
		}
	}()
	for range 20 {
		if err := s.Reconfigure(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
