package templates

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

var weekdays = []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}

// ScheduleText describes a 5-field cron expression for people ("daily
// 03:00", "weekly, Sun 04:00", "monthly, day 1 05:30", "hourly at :15",
// "custom schedule" otherwise) and, when enabled, appends when it fires
// next ("next in 3 h 43 min"), computed with robfig/cron's parser in now's
// location. An expression the parser rejects is "invalid schedule".
func ScheduleText(expr string, enabled bool, now time.Time) string {
	sched, err := cron.ParseStandard(expr)
	if err != nil {
		return "invalid schedule"
	}
	text := describeCron(expr)
	if !enabled {
		return text + ", auto-update off"
	}
	return text + ", next in " + Until(sched.Next(now).Sub(now))
}

func describeCron(expr string) string {
	f := strings.Fields(expr)
	if len(f) != 5 {
		return "custom schedule"
	}
	num := func(s string, lo, hi int) (int, bool) {
		n, err := strconv.Atoi(s)
		return n, err == nil && n >= lo && n <= hi
	}
	m, okM := num(f[0], 0, 59)
	h, okH := num(f[1], 0, 23)
	anyDom, anyMon, anyDow := f[2] == "*", f[3] == "*", f[4] == "*"
	if okM && f[1] == "*" && anyDom && anyMon && anyDow {
		return fmt.Sprintf("hourly at :%02d", m)
	}
	if !okM || !okH {
		return "custom schedule"
	}
	at := fmt.Sprintf("%02d:%02d", h, m)
	switch {
	case anyDom && anyMon && anyDow:
		return "daily " + at
	case anyDom && anyMon:
		if d, ok := num(f[4], 0, 7); ok {
			return "weekly, " + weekdays[d] + " " + at
		}
	case anyMon && anyDow:
		if d, ok := num(f[2], 1, 31); ok {
			return fmt.Sprintf("monthly, day %d %s", d, at)
		}
	}
	return "custom schedule"
}

// Until renders a positive duration coarsely: "1 d 16 h", "3 h 43 min",
// "12 min", "less than a minute".
func Until(d time.Duration) string {
	if d < time.Minute {
		return "less than a minute"
	}
	mins := int(d / time.Minute)
	days, hours, mins := mins/(24*60), mins/60%24, mins%60
	switch {
	case days > 0:
		if hours == 0 {
			return fmt.Sprintf("%d d", days)
		}
		return fmt.Sprintf("%d d %d h", days, hours)
	case hours > 0:
		if mins == 0 {
			return fmt.Sprintf("%d h", hours)
		}
		return fmt.Sprintf("%d h %d min", hours, mins)
	}
	return fmt.Sprintf("%d min", mins)
}

// RelTime renders t relative to now in now's location: "today 03:00",
// "yesterday 21:10", "2 days ago", "6 months ago", "1 year ago". A time in
// the future counts as today. The layout script recomputes it in the
// viewer's time zone.
func RelTime(t, now time.Time) string {
	t = t.In(now.Location())
	hm := t.Format("15:04")
	day := func(x time.Time) time.Time { return time.Date(x.Year(), x.Month(), x.Day(), 0, 0, 0, 0, x.Location()) }
	days := int(day(now).Sub(day(t)).Round(24*time.Hour) / (24 * time.Hour))
	switch {
	case t.After(now) || days <= 0:
		return "today " + hm
	case days == 1:
		return "yesterday " + hm
	case days < 30:
		return fmt.Sprintf("%d days ago", days)
	}
	months := (now.Year()-t.Year())*12 + int(now.Month()) - int(t.Month())
	if now.Day() < t.Day() {
		months--
	}
	months = max(months, 1)
	if months < 12 {
		if months == 1 {
			return "1 month ago"
		}
		return fmt.Sprintf("%d months ago", months)
	}
	if years := months / 12; years > 1 {
		return fmt.Sprintf("%d years ago", years)
	}
	return "1 year ago"
}

// HumanBytes renders a size as "2.3 MB" (1024-based, one decimal), "812 KB"
// or "512 B".
func HumanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MB"
	case n >= 1<<10:
		return strconv.FormatInt(n>>10, 10) + " KB"
	}
	return strconv.FormatInt(n, 10) + " B"
}
