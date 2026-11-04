package platform

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// NewLogger creates a structured logger that writes to stderr, to any extra
// writers (e.g. a FileLog) and to an in-memory ring buffer. The buffer can be
// used to expose recent log entries via the web UI.
func NewLogger(level string, extra ...io.Writer) (*slog.Logger, *LogBuffer) {
	return NewDaemonLogger(level, nil, extra...)
}

// NewDaemonLogger is NewLogger plus an optional syslog output. Syslog
// failures and dropped-line counts are reported through a logger over the
// other outputs only, so a broken syslog path never logs into itself.
func NewDaemonLogger(level string, sys *Syslog, extra ...io.Writer) (*slog.Logger, *LogBuffer) {
	lvl := parseLevel(level)
	buf := &LogBuffer{}
	handlers := []slog.Handler{buf.Handler(lvl)}
	for _, w := range append([]io.Writer{os.Stderr}, extra...) {
		handlers = append(handlers, slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl}))
	}
	if sys != nil {
		others := slog.New(&multiHandler{level: lvl, handlers: handlers})
		sys.SetNotify(func(msg string, args ...any) { others.Warn(msg, args...) })
		handlers = append(handlers[:len(handlers):len(handlers)], sys.Handler(lvl))
	}
	return slog.New(&multiHandler{level: lvl, handlers: handlers}), buf
}

// parseLevel maps a config log level to a slog level; unknown is info.
func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
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
