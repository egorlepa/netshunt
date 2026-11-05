package platform

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// SyslogSocket is the local syslog socket. On Keenetic it belongs to the
// firmware's ndm process, which keeps the system log and forwards it to the
// configured remote syslog server.
const SyslogSocket = "/dev/log"

const (
	syslogTag          = "netshunt"
	syslogQueueCap     = 512
	syslogMaxLine      = 1024
	syslogWriteTimeout = time.Second
	syslogBackoffMin   = time.Second
	syslogBackoffMax   = time.Minute
	syslogFacility     = 3 // daemon
)

// Syslog sends log lines to the local syslog socket as RFC3164 datagrams.
// Like FileLog it never blocks the caller: Handle renders the record and
// enqueues it into a bounded queue; a sender goroutine writes each datagram
// with a deadline. A send or dial error closes the connection; the next line
// after a backoff (1 s doubling to 1 min) redials, lines in between are
// dropped and counted. A stuck receiver costs the sender one deadline per
// backoff period and the caller nothing.
//
// Failures and recoveries are reported through notify, which the daemon
// points at the other log outputs, never at syslog itself.
type Syslog struct {
	path         string
	tag          string
	pid          int
	writeTimeout time.Duration
	notify       atomic.Pointer[func(msg string, args ...any)]

	mu      sync.RWMutex // guards closed against sends racing Close
	closed  bool
	lines   chan []byte
	dropped atomic.Int64
	total   atomic.Uint64 // cumulative drops, for metrics
	done    chan struct{}

	conn    net.Conn
	failing bool
	backoff time.Duration
	retryAt time.Time
}

// OpenSyslog starts the sender for SyslogSocket. It never fails: a missing
// socket is retried with backoff like any later error.
func OpenSyslog() *Syslog {
	return openSyslog(SyslogSocket, syslogWriteTimeout)
}

func openSyslog(path string, writeTimeout time.Duration) *Syslog {
	s := &Syslog{
		path:         path,
		tag:          syslogTag,
		pid:          os.Getpid(),
		writeTimeout: writeTimeout,
		lines:        make(chan []byte, syslogQueueCap),
		done:         make(chan struct{}),
	}
	go s.loop()
	return s
}

// SetNotify sets where syslog failures, recoveries and dropped-line counts
// are reported. It must not log into this Syslog.
func (s *Syslog) SetNotify(fn func(msg string, args ...any)) {
	s.notify.Store(&fn)
}

// Dropped returns the number of lines dropped and not yet reported.
func (s *Syslog) Dropped() int64 { return s.dropped.Load() }

// DroppedTotal returns the number of lines dropped since the output was
// opened (never reset by reporting).
func (s *Syslog) DroppedTotal() uint64 { return s.total.Load() }

// Handler returns a slog.Handler that sends records at or above level.
func (s *Syslog) Handler(level slog.Leveler) slog.Handler {
	return &syslogHandler{s: s, level: level}
}

// Close drains the queue and closes the socket. Later lines are discarded.
func (s *Syslog) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.lines)
	s.mu.Unlock()
	<-s.done
}

func (s *Syslog) enqueue(line []byte) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return
	}
	select {
	case s.lines <- line:
	default:
		s.dropped.Add(1)
		s.total.Add(1)
	}
}

func (s *Syslog) loop() {
	defer close(s.done)
	for line := range s.lines {
		s.send(line)
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

// send writes one datagram. A failed write on an established connection is
// retried once on a fresh one, which covers a restarted receiver; any other
// failure drops the line and starts the backoff.
func (s *Syslog) send(line []byte) {
	for attempt := 0; attempt < 2; attempt++ {
		if s.conn == nil {
			if time.Now().Before(s.retryAt) {
				break
			}
			c, err := net.Dial("unixgram", s.path)
			if err != nil {
				s.fail(err)
				break
			}
			s.conn = c
		}
		_ = s.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
		if _, err := s.conn.Write(line); err != nil {
			_ = s.conn.Close()
			s.conn = nil
			if attempt == 1 || isTimeout(err) {
				s.fail(err)
				break
			}
			continue
		}
		s.ok()
		return
	}
	s.dropped.Add(1)
	s.total.Add(1)
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func (s *Syslog) fail(err error) {
	if s.backoff == 0 {
		s.backoff = syslogBackoffMin
	} else {
		s.backoff = min(s.backoff*2, syslogBackoffMax)
	}
	s.retryAt = time.Now().Add(s.backoff)
	if !s.failing {
		s.failing = true
		s.report("syslog output unavailable, dropping lines until it recovers", "path", s.path, "error", err)
	}
}

func (s *Syslog) ok() {
	s.backoff = 0
	s.retryAt = time.Time{}
	recovered := s.failing
	s.failing = false
	n := s.dropped.Swap(0)
	if recovered {
		s.report("syslog output recovered", "path", s.path, "dropped", n)
	} else if n > 0 {
		s.report("syslog queue full, lines dropped", "dropped", n)
	}
}

func (s *Syslog) report(msg string, args ...any) {
	if fn := s.notify.Load(); fn != nil {
		(*fn)(msg, args...)
	}
}

// syslogSeverity maps a slog level to an RFC 5424 severity.
func syslogSeverity(l slog.Level) int {
	switch {
	case l >= slog.LevelError:
		return 3 // err
	case l >= slog.LevelWarn:
		return 4 // warning
	case l >= slog.LevelInfo:
		return 6 // info
	default:
		return 7 // debug
	}
}

// syslogHandler renders records as `<PRI>Mmm dd hh:mm:ss tag[pid]: msg
// key=value ...`, the format local syslog clients write to /dev/log. ndm
// rejects a line without the timestamp ("Core::Syslog: broken message") and
// shows the timestamp as given, so it is the record time in time.Local.
//
// Attributes are rendered by a slog.TextHandler created per record with the
// recorded WithAttrs/WithGroup calls replayed on it, so groups and
// preformatted attributes behave exactly as in the other outputs.
type syslogHandler struct {
	s     *Syslog
	level slog.Leveler
	ops   []func(slog.Handler) slog.Handler
}

func (h *syslogHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level.Level()
}

func (h *syslogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h.with(func(th slog.Handler) slog.Handler { return th.WithAttrs(attrs) })
}

func (h *syslogHandler) WithGroup(name string) slog.Handler {
	return h.with(func(th slog.Handler) slog.Handler { return th.WithGroup(name) })
}

func (h *syslogHandler) with(op func(slog.Handler) slog.Handler) slog.Handler {
	ops := make([]func(slog.Handler) slog.Handler, len(h.ops), len(h.ops)+1)
	copy(ops, h.ops)
	return &syslogHandler{s: h.s, level: h.level, ops: append(ops, op)}
}

func (h *syslogHandler) Handle(ctx context.Context, r slog.Record) error {
	var attrs bytes.Buffer
	var th slog.Handler = slog.NewTextHandler(&attrs, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && (a.Key == slog.LevelKey || a.Key == slog.MessageKey) {
				return slog.Attr{}
			}
			return a
		},
	})
	for _, op := range h.ops {
		th = op(th)
	}
	ts := r.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	r.Time = time.Time{} // TextHandler omits a zero time
	if err := th.Handle(ctx, r); err != nil {
		return err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "<%d>%s %s[%d]: ", syslogFacility*8+syslogSeverity(r.Level),
		ts.In(time.Local).Format(time.Stamp), h.s.tag, h.s.pid)
	b.WriteString(r.Message)
	if rest := bytes.TrimSpace(attrs.Bytes()); len(rest) > 0 {
		b.WriteByte(' ')
		b.Write(rest)
	}
	line := []byte(b.String())
	if len(line) > syslogMaxLine {
		cut := syslogMaxLine
		for cut > 0 && !utf8.RuneStart(line[cut]) {
			cut--
		}
		line = line[:cut]
	}
	// TextHandler quotes values with newlines; the message is raw.
	for i, c := range line {
		if c == '\n' || c == '\r' {
			line[i] = ' '
		}
	}
	h.s.enqueue(line)
	return nil
}
