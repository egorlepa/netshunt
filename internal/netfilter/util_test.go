package netfilter

import "testing"

const netstatSample = `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:10810           0.0.0.0:*               LISTEN      1/a
tcp        0      0 :::1081                 :::*                    LISTEN      888/hysteria
tcp        0      0 127.0.0.1:1082          0.0.0.0:*               TIME_WAIT   -
`

func TestListeningOn(t *testing.T) {
	tests := map[string]bool{":1081": true, "1081": true, ":1082": false, ":108": false, ":10810": true, ":80": false}
	for port, want := range tests {
		if got := listeningOn(netstatSample, port); got != want {
			t.Errorf("listeningOn(%q) = %v, want %v", port, got, want)
		}
	}
}
