package healthcheck

import (
	"context"
	"strings"
	"testing"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/platform/runnertest"
)

// healthyRouter scripts a router on which every rule the iptables check
// looks for exists (the fake answers every other command with success).
func healthyRouter() *runnertest.Fake {
	run := runnertest.New()
	run.On("ip rule show", "0:\tfrom all lookup local\n32000:\tfrom all fwmark 0x1 lookup 100 \n32766:\tfrom all lookup main", nil)
	run.On("ip route show table 100", "local default dev lo scope host", nil)
	return run
}

func iptablesCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Routing.LocalPort = 1081
	cfg.Network.EntwareInterface = "br0"
	cfg.Network.AdditionalInterfaces = []string{"awg0"}
	return &cfg
}

func TestIPTablesCheckAllPresent(t *testing.T) {
	r := checkIPTables4(context.Background(), iptablesCfg(), healthyRouter())
	if !r.Passed || r.Warn {
		t.Fatalf("result = %+v", r)
	}
}

func TestIPTablesCheckMissingTproxyFails(t *testing.T) {
	cases := []struct {
		name, prefix, want string
	}{
		{"tproxy rule", "iptables -w -t mangle -C NSHUNT_UDP", "udp tproxy"},
		{"mangle chain", "iptables -w -t mangle -L NSHUNT_UDP", "NSHUNT_UDP chain"},
		{"mangle jump", "iptables -w -t mangle -C PREROUTING -i awg0 -j NSHUNT_UDP", "mangle prerouting jump (awg0)"},
		{"policy rule", "ip rule show", "tproxy policy route"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run := healthyRouter()
			run.On(c.prefix, "", runnertest.ErrScripted)
			r := checkIPTables4(context.Background(), iptablesCfg(), run)
			if r.Passed || r.Warn {
				t.Fatalf("missing %s: result = %+v, want a failure", c.name, r)
			}
			if !strings.Contains(r.Detail, c.want) {
				t.Fatalf("detail %q lacks %q", r.Detail, c.want)
			}
		})
	}
}
