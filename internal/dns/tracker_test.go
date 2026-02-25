package dns

import (
	"context"
	"log/slog"
	"testing"

	"github.com/egorlepa/netshunt/internal/netfilter"
)

// newTestTracker returns a tracker with a dummy ipset name.
// ipset commands will fail silently (not on a real router), which is fine
// for unit-testing the in-memory maps.
func newTestTracker() *Tracker {
	ipset := netfilter.NewIPSet("test_tracker")
	return NewTracker(ipset, slog.Default())
}

func TestTrackerTrackAndCount(t *testing.T) {
	tr := newTestTracker()
	ctx := context.Background()

	tr.Track(ctx, "example.com", "1.2.3.4")
	tr.Track(ctx, "example.com", "1.2.3.5")
	tr.Track(ctx, "other.com", "1.2.3.4") // shared IP

	domains, ips := tr.Count()
	if domains != 2 {
		t.Errorf("domains = %d, want 2", domains)
	}
	if ips != 2 {
		t.Errorf("ips = %d, want 2", ips)
	}
}

func TestTrackerTrackNoDuplicates(t *testing.T) {
	tr := newTestTracker()
	ctx := context.Background()

	tr.Track(ctx, "example.com", "1.2.3.4")
	tr.Track(ctx, "example.com", "1.2.3.4")
	tr.Track(ctx, "example.com", "1.2.3.4")

	domains, ips := tr.Count()
	if domains != 1 || ips != 1 {
		t.Errorf("after duplicate tracks: domains=%d, ips=%d, want 1,1", domains, ips)
	}
}

func TestTrackerRemoveDomain(t *testing.T) {
	tr := newTestTracker()
	ctx := context.Background()

	tr.Track(ctx, "example.com", "1.2.3.4")
	tr.Track(ctx, "other.com", "1.2.3.4")

	// Remove example.com — IP still referenced by other.com.
	tr.RemoveDomain(ctx, "example.com")

	domains, ips := tr.Count()
	if domains != 1 {
		t.Errorf("domains = %d, want 1", domains)
	}
	if ips != 1 {
		t.Errorf("ips = %d, want 1 (still referenced by other.com)", ips)
	}

	// Remove other.com — IP now unreferenced.
	tr.RemoveDomain(ctx, "other.com")

	domains, ips = tr.Count()
	if domains != 0 {
		t.Errorf("domains = %d, want 0", domains)
	}
	if ips != 0 {
		t.Errorf("ips = %d, want 0", ips)
	}
}

func TestTrackerFlush(t *testing.T) {
	tr := newTestTracker()
	ctx := context.Background()

	tr.Track(ctx, "a.com", "1.1.1.1")
	tr.Track(ctx, "b.com", "2.2.2.2")
	tr.Flush(ctx)

	domains, ips := tr.Count()
	if domains != 0 || ips != 0 {
		t.Errorf("after flush: domains=%d, ips=%d, want 0,0", domains, ips)
	}
}
