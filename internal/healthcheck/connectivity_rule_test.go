package healthcheck

import (
	"strings"
	"testing"
)

func TestIsConnectivityRule(t *testing.T) {
	tests := []struct {
		rule string
		want bool
	}{
		{"OUTPUT -p tcp -m tcp --dport 80 -m mark --mark 0x6e730026 -j REDIRECT --to-ports 1081", true},
		{"OUTPUT -p tcp -m mark --mark 0x6e73ffff/0xffffffff -j REDIRECT --to-ports 1081", true},
		{"OUTPUT -p tcp -m mark --mark 0x1 -j REDIRECT --to-ports 1081", false},
		{"OUTPUT -p tcp -m mark --mark 0x6e740001 -j REDIRECT --to-ports 1081", false},
		{"OUTPUT -d 10.0.0.1/32 -j ACCEPT", false},
	}
	for _, tt := range tests {
		// Drop the chain name: ListRules returns specs after "-A <chain>".
		fields := strings.Fields(tt.rule)[1:]
		if got := isConnectivityRule(fields); got != tt.want {
			t.Errorf("isConnectivityRule(%q) = %v, want %v", tt.rule, got, tt.want)
		}
	}
}
