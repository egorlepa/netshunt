package platform

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

const logBufferCap = 500

// LogEntry holds one structured log record captured from the slog pipeline.
type LogEntry struct {
	Time  time.Time
	Level string // "DEBUG", "INFO", "WARN", "ERROR"
	Msg   string
	Attrs string // formatted key=value pairs, empty if none
}

// LogBuffer is a thread-safe in-memory ring buffer of structured log entries.
type LogBuffer struct {
	mu      sync.Mutex
	entries []LogEntry
}

// Entries returns all buffered entries newest-first.
func (b *LogBuffer) Entries() []LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]LogEntry, len(b.entries))
	for i, e := range b.entries {
		out[len(b.entries)-1-i] = e
	}
	return out
}

func (b *LogBuffer) appendEntry(e LogEntry) {
	b.mu.Lock()
	if len(b.entries) >= logBufferCap {
		b.entries = b.entries[1:]
	}
	b.entries = append(b.entries, e)
	b.mu.Unlock()
}

// Handler returns a slog.Handler that writes to this buffer at the given minimum level.
func (b *LogBuffer) Handler(level slog.Level) slog.Handler {
	return &logBufHandler{buf: b, minLevel: level}
}

// logBufHandler implements slog.Handler and writes records into the parent LogBuffer.
type logBufHandler struct {
	buf      *LogBuffer
	minLevel slog.Level
	preAttrs []slog.Attr
}

func (h *logBufHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.minLevel
}

func (h *logBufHandler) Handle(_ context.Context, r slog.Record) error {
	var parts []string
	for _, a := range h.preAttrs {
		parts = append(parts, fmtAttr(a))
	}
	r.Attrs(func(a slog.Attr) bool {
		parts = append(parts, fmtAttr(a))
		return true
	})
	h.buf.appendEntry(LogEntry{
		Time:  r.Time,
		Level: r.Level.String(),
		Msg:   r.Message,
		Attrs: strings.Join(parts, " "),
	})
	return nil
}

func (h *logBufHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	combined := make([]slog.Attr, len(h.preAttrs)+len(attrs))
	copy(combined, h.preAttrs)
	copy(combined[len(h.preAttrs):], attrs)
	return &logBufHandler{buf: h.buf, minLevel: h.minLevel, preAttrs: combined}
}

func (h *logBufHandler) WithGroup(_ string) slog.Handler {
	return h // groups are flattened; sufficient for this use case
}

func fmtAttr(a slog.Attr) string {
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		s := v.String()
		if strings.ContainsAny(s, " \t\n") {
			return fmt.Sprintf("%s=%q", a.Key, s)
		}
		return a.Key + "=" + s
	case slog.KindAny:
		if err, ok := v.Any().(error); ok {
			msg := err.Error()
			if strings.ContainsAny(msg, " \t\n") {
				return fmt.Sprintf("%s=%q", a.Key, msg)
			}
			return a.Key + "=" + msg
		}
		return fmt.Sprintf("%s=%v", a.Key, v.Any())
	default:
		return fmt.Sprintf("%s=%v", a.Key, v)
	}
}
