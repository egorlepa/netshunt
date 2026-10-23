package netfilter

import (
	"context"
	"testing"

	"github.com/egorlepa/netshunt/internal/platform/runnertest"
)

// Captured from the router: `iptables -t filter -L NSHUNT_KS -v -x -n`.
const ksListing = `Chain NSHUNT_KS (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       0        0 RETURN     all  --  *      *       0.0.0.0/0            10.0.0.0/8
       0        0 RETURN     all  --  *      *       0.0.0.0/0            172.16.0.0/12
    1534    92040 RETURN     all  --  *      *       0.0.0.0/0            192.168.0.0/16
      22     1320 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set bypass dst
`

func TestParseDropPackets(t *testing.T) {
	if got := ParseDropPackets(ksListing); got != 22 {
		t.Errorf("drops = %d, want 22", got)
	}
	if got := ParseDropPackets(ksListing + "       3      180 DROP       udp  --  *      *       0.0.0.0/0            0.0.0.0/0\n"); got != 25 {
		t.Errorf("two DROP rules = %d, want 25", got)
	}
	if got := ParseDropPackets("Chain NSHUNT_KS (1 references)\n    pkts      bytes target     prot opt in     out     source               destination\n"); got != 0 {
		t.Errorf("empty chain = %d", got)
	}
	if got := ParseDropPackets(""); got != 0 {
		t.Errorf("no output = %d", got)
	}
}

func TestDropPacketsMissingChain(t *testing.T) {
	f := runnertest.New()
	f.On("iptables -w -t filter -L NSHUNT_KS -n", "", runnertest.ErrScripted)
	n, err := (&IPTables{Runner: f}).DropPackets(context.Background(), "filter", "NSHUNT_KS")
	if n != 0 || err != nil {
		t.Fatalf("missing chain: %d %v", n, err)
	}

	f = runnertest.New()
	f.On("iptables -w -t filter -L NSHUNT_KS -v -x -n", ksListing, nil)
	n, err = (&IPTables{Runner: f}).DropPackets(context.Background(), "filter", "NSHUNT_KS")
	if n != 22 || err != nil {
		t.Fatalf("chain: %d %v", n, err)
	}
}
