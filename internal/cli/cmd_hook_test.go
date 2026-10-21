package cli

import (
	"strings"
	"testing"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/deploy"
)

func TestIfstateShouldReconcile(t *testing.T) {
	t.Setenv("system_name", "")
	t.Setenv("SYSTEM_NAME", "")
	cfg := config.Defaults()
	cfg.Network.EntwareInterface = "br0"
	cfg.Network.AdditionalInterfaces = []string{"awg0"}

	cases := []struct {
		ev   ifstateEvent
		want bool
	}{
		{ifstateEvent{id: "Wireguard0", systemName: "awg0", link: "down", connected: "no", up: "down"}, false},
		{ifstateEvent{systemName: "awg0", link: "down", connected: "yes", up: "up"}, false},
		{ifstateEvent{systemName: "awg0", link: "up", connected: "yes", up: "up"}, true},
		{ifstateEvent{systemName: "br0", connected: "yes"}, true},
		{ifstateEvent{systemName: "br0", up: "up"}, true},
		{ifstateEvent{systemName: "eth3", link: "up", connected: "yes", up: "up"}, false},
		{ifstateEvent{id: "Bridge0", link: "up", connected: "yes"}, false},
		{ifstateEvent{systemName: "br0"}, false},
	}
	for _, c := range cases {
		if got := c.ev.shouldReconcile(&cfg); got != c.want {
			t.Errorf("%+v: shouldReconcile = %v, want %v", c.ev, got, c.want)
		}
	}

	t.Setenv("system_name", "awg0")
	if !(ifstateEvent{id: "Wireguard0", link: "up"}).shouldReconcile(&cfg) {
		t.Error("system_name from the environment ignored")
	}
}

func TestIfstateScriptPassesSystemName(t *testing.T) {
	data, err := deploy.NDMScript("ifstatechanged.d", "100-ifstate")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `--system-name="$system_name"`) {
		t.Fatalf("ifstate script does not pass system_name:\n%s", data)
	}
	for _, flag := range []string{"--id=", "--connected=", "--link=", "--up="} {
		if !strings.Contains(string(data), flag) {
			t.Errorf("ifstate script lacks %s", flag)
		}
	}
}

// The netfilter hook must fire for every table netshunt has rules in: nat
// (TCP redirect, DNS), mangle (TPROXY) and filter (FORWARD kill switch).
func TestNetfilterScriptMatchesOurTables(t *testing.T) {
	data, err := deploy.NDMScript("netfilter.d", "100-proxy-redirect")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"nat", "mangle", "filter"} {
		if !strings.Contains(string(data), `[ "$table" = "`+table+`" ]`) {
			t.Errorf("netfilter script ignores table %s:\n%s", table, data)
		}
	}
	if !strings.Contains(string(data), `hook netfilter "$type" "$table"`) {
		t.Errorf("netfilter script does not call the hook:\n%s", data)
	}
}
