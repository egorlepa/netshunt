package netfilter

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/vishvananda/netlink/nl"
)

// Backend names, as reported by IPSet.Backend and Conntrack.Backend.
const (
	BackendNetlink = "netlink"
	BackendExec    = "exec"
)

// EnvBackend overrides the backend selection: "exec" never opens a netlink
// socket. Anything else (unset, "auto") tries netlink and falls back to exec.
const EnvBackend = "NETSHUNT_NETFILTER"

// forceExec reports whether EnvBackend pins the exec backend.
func forceExec() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(EnvBackend)), BackendExec)
}

// Option configures NewIPSet and NewConntrack.
type Option func(*options)

type options struct {
	logger *slog.Logger
}

// WithLogger sets the logger for the backend selection and fallback lines.
// Default: slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(o *options) { o.logger = l }
}

func buildOptions(opts []Option) options {
	o := options{}
	for _, f := range opts {
		f(&o)
	}
	if o.logger == nil {
		o.logger = slog.Default()
	}
	return o
}

// transportError marks a failure of the netlink transport itself (socket
// closed, protocol unsupported, permission denied, a panic in the library),
// as opposed to an answer of the kernel (set full, set missing). Only a
// transport error switches a backend to exec.
type transportError struct{ err error }

func (e *transportError) Error() string { return "netlink transport: " + e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

// isTransport reports whether err is (or wraps) a transport error.
func isTransport(err error) bool {
	var te *transportError
	return errors.As(err, &te)
}

// classify wraps errors of the netlink layer that mean the transport is
// broken into a transportError. Kernel answers (ipset error codes, ENOENT,
// EEXIST, ...) and everything else are returned unchanged.
func classify(err error) error {
	if err == nil || isTransport(err) {
		return err
	}
	// "use of closed file" is internal/poll.ErrFileClosing, which the
	// netlink socket's raw conn returns unwrapped.
	if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) ||
		strings.Contains(err.Error(), "use of closed file") {
		return &transportError{err}
	}
	var ipsetErr nl.IPSetError
	if errors.As(err, &ipsetErr) {
		return err
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && transportErrno(errno) {
		return &transportError{err}
	}
	return err
}

// transportErrno lists the errnos that come from the socket or the netlink
// family, never from a well-formed ipset/conntrack request on a working
// socket. EAGAIN is the receive timeout of the socket.
func transportErrno(e syscall.Errno) bool {
	switch e {
	case syscall.EBADF, syscall.ENOTSOCK, syscall.EPROTO, syscall.EOPNOTSUPP,
		syscall.EPERM, syscall.EACCES, syscall.EPROTONOSUPPORT, syscall.EAFNOSUPPORT,
		syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.EPIPE, syscall.ENOBUFS,
		syscall.EAGAIN, syscall.ETIMEDOUT, syscall.ENOSYS:
		return true
	}
	return false
}

// guard runs one call into the netlink library. A panic inside it (the
// library type-asserts errors it does not expect) becomes a transport error
// instead of taking the daemon down.
func guard(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &transportError{fmt.Errorf("panic: %v", r)}
		}
	}()
	return classify(fn())
}

// fallback routes calls to a netlink backend until its transport breaks,
// then to exec for the rest of the process. The failing call is retried
// once through exec, so callers see no difference.
type fallback[B any] struct {
	what   string // "ipset", "conntrack": log prefix
	nl     B
	active atomic.Bool
	once   sync.Once
	logger *slog.Logger
}

func newFallback[B any](what string, nlBackend B, logger *slog.Logger) *fallback[B] {
	f := &fallback[B]{what: what, nl: nlBackend, logger: logger}
	f.active.Store(true)
	return f
}

// do runs call on the netlink backend, or on exec once netlink is gone.
func (f *fallback[B]) do(op string, exec B, call func(B) error) error {
	if f.active.Load() {
		err := call(f.nl)
		if !isTransport(err) {
			return err
		}
		f.disable(op, err)
	}
	return call(exec)
}

func (f *fallback[B]) disable(op string, err error) {
	f.active.Store(false)
	f.once.Do(func() {
		f.logger.Warn(f.what+": netlink failed, switching to exec", "op", op, "error", err)
	})
}

// backend names the backend calls currently go to.
func (f *fallback[B]) backend() string {
	if f != nil && f.active.Load() {
		return BackendNetlink
	}
	return BackendExec
}
