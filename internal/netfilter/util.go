package netfilter

import (
	"context"
	"strings"

	"github.com/egorlepa/netshunt/internal/platform"
)

// CheckListeningPort returns true if something is listening on the given port string (e.g., ":1181").
func CheckListeningPort(ctx context.Context, port string) (bool, error) {
	out, err := platform.Run(ctx, "netstat", "-tlnp")
	if err != nil {
		return false, err
	}
	return strings.Contains(out, port), nil
}
