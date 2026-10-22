package platform

import (
	"bytes"
	"context"
	"log"
	"log/slog"
)

// RouteStdLog sends everything written through the standard library's
// package-level logger (used by dependencies such as vishvananda/netlink for
// "unknown attribute" notices) to logger at Debug level, so it lands in the
// daemon log instead of a stderr that start-stop-daemon discards.
func RouteStdLog(logger *slog.Logger) {
	log.SetFlags(0)
	log.SetOutput(stdLogWriter{logger: logger})
}

type stdLogWriter struct{ logger *slog.Logger }

func (w stdLogWriter) Write(p []byte) (int, error) {
	for _, line := range bytes.Split(bytes.TrimRight(p, "\n"), []byte("\n")) {
		if len(line) > 0 {
			w.logger.Log(context.Background(), slog.LevelDebug, string(line), "source", "stdlog")
		}
	}
	return len(p), nil
}
