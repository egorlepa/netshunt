package templates

import (
	"testing"
	"time"
)

func TestScheduleText(t *testing.T) {
	// Thursday 2026-10-22 23:17 local.
	now := time.Date(2026, 10, 22, 23, 17, 0, 0, time.Local)
	tests := []struct {
		expr    string
		enabled bool
		want    string
	}{
		{"0 3 * * *", true, "daily 03:00, next in 3 h 43 min"},
		{"0 4 * * 0", true, "weekly, Sun 04:00, next in 2 d 4 h"},
		{"30 5 1 * *", true, "monthly, day 1 05:30, next in 9 d 6 h"},
		{"15 * * * *", true, "hourly at :15, next in 58 min"},
		{"*/5 * * * *", true, "custom schedule, next in 3 min"},
		{"0 23 * * *", true, "daily 23:00, next in 23 h 43 min"},
		{"0 3 * * *", false, "daily 03:00, auto-update off"},
		{"bogus", true, "invalid schedule"},
	}
	for _, tt := range tests {
		if got := ScheduleText(tt.expr, tt.enabled, now); got != tt.want {
			t.Errorf("ScheduleText(%q) = %q, want %q", tt.expr, got, tt.want)
		}
	}
}

func TestUntil(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "less than a minute"},
		{12*time.Minute + 59*time.Second, "12 min"},
		{3*time.Hour + 43*time.Minute, "3 h 43 min"},
		{2 * time.Hour, "2 h"},
		{40 * time.Hour, "1 d 16 h"},
		{48 * time.Hour, "2 d"},
	}
	for _, tt := range tests {
		if got := Until(tt.d); got != tt.want {
			t.Errorf("Until(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestRelTime(t *testing.T) {
	now := time.Date(2026, 10, 22, 23, 17, 0, 0, time.Local)
	tests := []struct {
		t    time.Time
		want string
	}{
		{time.Date(2026, 10, 22, 3, 0, 0, 0, time.Local), "today 03:00"},
		{time.Date(2026, 10, 23, 1, 0, 0, 0, time.Local), "today 01:00"}, // clock skew: future
		{time.Date(2026, 10, 21, 21, 10, 0, 0, time.Local), "yesterday 21:10"},
		{time.Date(2026, 10, 20, 23, 59, 0, 0, time.Local), "2 days ago"},
		{time.Date(2026, 9, 25, 12, 0, 0, 0, time.Local), "27 days ago"},
		{time.Date(2026, 9, 20, 12, 0, 0, 0, time.Local), "1 month ago"},
		{time.Date(2026, 4, 19, 4, 29, 0, 0, time.Local), "6 months ago"},
		{time.Date(2025, 10, 23, 4, 29, 0, 0, time.Local), "11 months ago"},
		{time.Date(2025, 9, 1, 0, 0, 0, 0, time.Local), "1 year ago"},
		{time.Date(2023, 1, 1, 0, 0, 0, 0, time.Local), "3 years ago"},
	}
	for _, tt := range tests {
		if got := RelTime(tt.t, now); got != tt.want {
			t.Errorf("RelTime(%v) = %q, want %q", tt.t, got, tt.want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{2360003: "2.3 MB", 5347737: "5.1 MB", 832000: "812 KB", 512: "512 B"} {
		if got := HumanBytes(n); got != want {
			t.Errorf("HumanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
