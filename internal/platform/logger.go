package platform

import (
	"context"
	"log/slog"
	"os"
)

// NewLogger creates a structured logger that writes to stderr and to an
// in-memory ring buffer. The buffer can be used to expose recent log entries
// via the web UI.
func NewLogger(level string) (*slog.Logger, *LogBuffer) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	buf := &LogBuffer{}
	stderr := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	return slog.New(&multiHandler{
		level:    lvl,
		handlers: []slog.Handler{stderr, buf.Handler(lvl)},
	}), buf
}

// multiHandler fans log records out to multiple slog.Handler implementations.
type multiHandler struct {
	level    slog.Level
	handlers []slog.Handler
}

func (m *multiHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= m.level }

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range m.handlers {
		if h.Enabled(ctx, r.Level) {
			_ = h.Handle(ctx, r)
		}
	}
	return nil
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	hs := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		hs[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{level: m.level, handlers: hs}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	hs := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		hs[i] = h.WithGroup(name)
	}
	return &multiHandler{level: m.level, handlers: hs}
}
