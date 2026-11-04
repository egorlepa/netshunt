package platform

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// listenGram opens a unixgram receiver at path.
func listenGram(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func recvLine(t *testing.T, c *net.UnixConn) string {
	t.Helper()
	buf := make([]byte, 4096)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no datagram: %v", err)
	}
	return string(buf[:n])
}

// notes collects notify calls.
type notes struct {
	mu   sync.Mutex
	msgs []string
}

func (n *notes) fn(msg string, args ...any) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.msgs = append(n.msgs, fmt.Sprintln(append([]any{msg}, args...)...))
}

func (n *notes) find(sub string) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, m := range n.msgs {
		if strings.Contains(m, sub) {
			return m
		}
	}
	return ""
}

func socketPath(t *testing.T) string {
	// sun_path is limited to 108 bytes; t.TempDir() can be long.
	dir, err := os.MkdirTemp("", "nsl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "log")
}

func TestSyslogFormatAndSeverity(t *testing.T) {
	path := socketPath(t)
	rx := listenGram(t, path)
	s := openSyslog(path, time.Second)
	defer s.Close()
	log := slog.New(s.Handler(slog.LevelDebug))

	head := regexp.MustCompile(`^<(\d+)>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d netshunt\[(\d+)\]: (.*)$`)
	cases := []struct {
		log  func(string, ...any)
		pri  string
		want string
	}{
		{log.Debug, "31", "dbg"},
		{log.Info, "30", `daemon started version=1.2.3 note="a b"`},
		{log.Warn, "28", "careful n=7"},
		{log.Error, "27", `boom error="x\ny"`},
	}
	cases[0].log("dbg")
	cases[1].log("daemon started", "version", "1.2.3", "note", "a b")
	cases[2].log("careful", "n", 7)
	cases[3].log("boom", "error", "x\ny")
	for _, c := range cases {
		line := recvLine(t, rx)
		m := head.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("bad line %q", line)
		}
		if m[1] != c.pri || m[2] != fmt.Sprint(os.Getpid()) || m[3] != c.want {
			t.Errorf("got %q, want pri %s msg %q", line, c.pri, c.want)
		}
	}
}

func TestSyslogAttrsGroupsAndLevel(t *testing.T) {
	path := socketPath(t)
	rx := listenGram(t, path)
	s := openSyslog(path, time.Second)
	defer s.Close()
	log := slog.New(s.Handler(slog.LevelInfo)).With("comp", "dns").WithGroup("g").With("a", 1)

	log.Debug("hidden")
	log.Info("multi\nline msg", "b", 2)
	line := recvLine(t, rx)
	if !strings.HasSuffix(line, ": multi line msg comp=dns g.a=1 g.b=2") {
		t.Errorf("got %q", line)
	}
}

func TestSyslogTruncates(t *testing.T) {
	path := socketPath(t)
	rx := listenGram(t, path)
	s := openSyslog(path, time.Second)
	defer s.Close()
	slog.New(s.Handler(slog.LevelInfo)).Info(strings.Repeat("ж", 2000))
	line := recvLine(t, rx)
	if len(line) > syslogMaxLine || len(line) < syslogMaxLine-1 {
		t.Errorf("len %d", len(line))
	}
	if !strings.HasSuffix(line, "ж") {
		t.Errorf("cut inside a rune: %q", line[len(line)-4:])
	}
}

// A receiver that never reads: the socket buffer fills, sends hit the
// deadline, yet logging returns at once and the lines are counted.
func TestSyslogNeverBlocks(t *testing.T) {
	path := socketPath(t)
	rx := listenGram(t, path)
	_ = rx.SetReadBuffer(1)
	s := openSyslog(path, 50*time.Millisecond)
	var n notes
	s.SetNotify(n.fn)
	log := slog.New(s.Handler(slog.LevelInfo))

	const total = 20000
	start := time.Now()
	for i := range total {
		log.Info("flood", "i", i, "pad", strings.Repeat("x", 200))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("logging %d lines took %v", total, d)
	}
	deadline := time.Now().Add(3 * time.Second)
	for n.find("unavailable") == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n.find("unavailable") == "" {
		t.Fatal("stuck receiver not reported")
	}
	if s.Dropped() == 0 {
		t.Error("no dropped lines counted")
	}
	s.Close()
}

func TestSyslogMissingSocketThenRecovers(t *testing.T) {
	path := socketPath(t)
	s := openSyslog(path, time.Second)
	defer s.Close()
	var n notes
	s.SetNotify(n.fn)
	log := slog.New(s.Handler(slog.LevelInfo))

	log.Info("lost")
	waitFor(t, func() bool { return n.find("unavailable") != "" })
	rx := listenGram(t, path)
	// The first retry is 1 s after the failure.
	time.Sleep(syslogBackoffMin + 100*time.Millisecond)
	log.Info("back")
	if line := recvLine(t, rx); !strings.HasSuffix(line, ": back") {
		t.Errorf("got %q", line)
	}
	waitFor(t, func() bool { return strings.Contains(n.find("recovered"), "dropped 1") })
}

// The receiver socket is recreated (ndm restart): the next line goes to the
// new socket without loss.
func TestSyslogReconnects(t *testing.T) {
	path := socketPath(t)
	rx := listenGram(t, path)
	s := openSyslog(path, time.Second)
	defer s.Close()
	log := slog.New(s.Handler(slog.LevelInfo))

	log.Info("one")
	if line := recvLine(t, rx); !strings.HasSuffix(line, ": one") {
		t.Fatalf("got %q", line)
	}
	_ = rx.Close()
	_ = os.Remove(path)
	rx2 := listenGram(t, path)
	log.Info("two")
	if line := recvLine(t, rx2); !strings.HasSuffix(line, ": two") {
		t.Errorf("got %q", line)
	}
	if s.Dropped() != 0 {
		t.Errorf("dropped %d", s.Dropped())
	}
}

// NewDaemonLogger reports syslog trouble into the other outputs only.
func TestDaemonLoggerNotifiesOtherOutputs(t *testing.T) {
	s := openSyslog(socketPath(t), time.Second)
	defer s.Close()
	log, buf := NewDaemonLogger("info", s)
	log.Info("first")
	waitFor(t, func() bool {
		for _, e := range buf.Entries() {
			if strings.Contains(e.Msg, "syslog output unavailable") {
				return true
			}
		}
		return false
	})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
