package platform

import (
	"bytes"
	"log"
	"log/slog"
	"strings"
	"testing"
)

func TestRouteStdLog(t *testing.T) {
	var buf bytes.Buffer
	RouteStdLog(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { log.SetOutput(nil); log.SetFlags(log.LstdFlags) })
	log.Printf("netlink: unknown attribute %d", 24)
	out := buf.String()
	if !strings.Contains(out, "level=DEBUG") || !strings.Contains(out, "unknown attribute 24") || !strings.Contains(out, "source=stdlog") {
		t.Fatalf("std log not routed: %q", out)
	}
}
