package platform

import (
	"errors"
	"log/slog"
	"reflect"
	"testing"
)

func TestLogBufferKeepsStructuredAttrs(t *testing.T) {
	buf := &LogBuffer{}
	log := slog.New(buf.Handler(slog.LevelInfo)).With("component", "dns")
	log.Info("blocklist applied", "domains", 206567, "per_source", "map[a:1 b:2]", "error", errors.New("boom"))
	e := buf.Entries()
	if len(e) != 1 {
		t.Fatalf("entries: %d", len(e))
	}
	want := []LogAttr{{"component", "dns"}, {"domains", "206567"}, {"per_source", `"map[a:1 b:2]"`}, {"error", "boom"}}
	if !reflect.DeepEqual(e[0].KV, want) {
		t.Errorf("KV = %#v", e[0].KV)
	}
	if e[0].Attrs != "component=dns\ndomains=206567\nper_source=\"map[a:1 b:2]\"\nerror=boom" {
		t.Errorf("Attrs = %q", e[0].Attrs)
	}
}
