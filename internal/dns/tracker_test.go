package dns

import (
	"context"
	"log/slog"
	"testing"

	"github.com/egorlepa/netshunt/internal/netfilter"
)

// newTestTracker returns a tracker with dummy ipset names.
// ipset commands will fail silently (not on a real router), which is fine
// for unit-testing the in-memory maps.
func newTestTracker() *Tracker {
	ipset4 := netfilter.NewIPSet("test_tracker")
	ipset6 := netfilter.NewIPSet6("test_tracker6")
	return NewTracker(ipset4, ipset6, slog.Default())
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

func TestTrackerIPv6(t *testing.T) {
	tr := newTestTracker()
	ctx := context.Background()

	tr.Track(ctx, "example.com", "1.2.3.4")
	tr.Track(ctx, "example.com", "2001:db8::1")
	tr.Track(ctx, "other.com", "2001:db8::2")

	domains, ips := tr.Count()
	if domains != 2 {
		t.Errorf("domains = %d, want 2", domains)
	}
	if ips != 3 {
		t.Errorf("ips = %d, want 3", ips)
	}
}

func TestTrackerRemoveDomainIPv6(t *testing.T) {
	tr := newTestTracker()
	ctx := context.Background()

	tr.Track(ctx, "example.com", "2001:db8::1")
	tr.Track(ctx, "other.com", "2001:db8::1") // shared IPv6

	tr.RemoveDomain(ctx, "example.com")

	domains, ips := tr.Count()
	if domains != 1 {
		t.Errorf("domains = %d, want 1", domains)
	}
	if ips != 1 {
		t.Errorf("ips = %d, want 1 (still referenced by other.com)", ips)
	}

	tr.RemoveDomain(ctx, "other.com")

	domains, ips = tr.Count()
	if domains != 0 || ips != 0 {
		t.Errorf("after removing all: domains=%d, ips=%d, want 0,0", domains, ips)
	}
}

func TestTrackerNilIPv6(t *testing.T) {
	// When IPv6 is disabled, ipset6 is nil. Tracker should still work for IPv4.
	ipset4 := netfilter.NewIPSet("test_tracker_v4only")
	tr := NewTracker(ipset4, nil, slog.Default())
	ctx := context.Background()

	tr.Track(ctx, "example.com", "1.2.3.4")

	domains, ips := tr.Count()
	if domains != 1 || ips != 1 {
		t.Errorf("domains=%d, ips=%d, want 1,1", domains, ips)
	}

	tr.Flush(ctx)

	domains, ips = tr.Count()
	if domains != 0 || ips != 0 {
		t.Errorf("after flush: domains=%d, ips=%d, want 0,0", domains, ips)
	}
}

func TestIsIPv6(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"1.2.3.4", false},
		{"10.0.0.1", false},
		{"2001:db8::1", true},
		{"::1", true},
		{"fe80::1", true},
	}
	for _, tt := range tests {
		if got := isIPv6(tt.ip); got != tt.want {
			t.Errorf("isIPv6(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}
