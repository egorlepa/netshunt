package netfilter

import (
	"context"
	"strings"

	"github.com/egorlepa/netshunt/internal/platform"
)

// CheckListeningPort reports whether a TCP socket is listening on the given
// port (":1081"). It compares the port part of netstat's local-address column
// exactly, so ":1081" does not match ":10810".
func CheckListeningPort(ctx context.Context, port string) (bool, error) {
	out, err := platform.Run(ctx, "netstat", "-tlnp")
	if err != nil {
		return false, err
	}
	return listeningOn(out, port), nil
}

// listeningOn scans netstat -tln style output for a LISTEN line whose local
// address ends in port (":1081" or the bare "1081").
func listeningOn(out, port string) bool {
	port = ":" + strings.TrimPrefix(port, ":")
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		// Proto Recv-Q Send-Q Local-Address Foreign-Address State ...
		if len(fields) < 6 || fields[5] != "LISTEN" {
			continue
		}
		local := fields[3]
		if i := strings.LastIndex(local, ":"); i >= 0 && local[i:] == port {
			return true
		}
	}
	return false
}
