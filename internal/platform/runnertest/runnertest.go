// Package runnertest provides a fake platform.Runner for tests.
package runnertest

import (
	"context"
	"errors"
	"strings"
	"sync"
)

// Response is a scripted result for commands starting with a prefix.
type Response struct {
	Out string
	Err error
}

// Fake is a platform.Runner that records every command and answers from
// Handler, then from scripted responses matched by the longest command-line
// prefix, then with ("", nil).
type Fake struct {
	mu        sync.Mutex
	calls     []string
	responses map[string]Response

	// Handler, when set, answers every command. handled=false falls through
	// to the scripted responses.
	Handler func(name string, args []string) (out string, err error, handled bool)
}

// New returns an empty Fake.
func New() *Fake {
	return &Fake{responses: map[string]Response{}}
}

// ErrScripted is a generic failure for scripted responses.
var ErrScripted = errors.New("scripted failure")

// On scripts the response for every command line starting with prefix.
func (f *Fake) On(prefix, out string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses[prefix] = Response{Out: out, Err: err}
}

// Run implements platform.Runner.
func (f *Fake) Run(_ context.Context, name string, args ...string) (string, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.mu.Lock()
	f.calls = append(f.calls, line)
	h := f.Handler
	f.mu.Unlock()

	if h != nil {
		if out, err, ok := h(name, args); ok {
			return out, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	best, found := "", false
	for p := range f.responses {
		if strings.HasPrefix(line, p) && len(p) >= len(best) {
			best, found = p, true
		}
	}
	if found {
		r := f.responses[best]
		return r.Out, r.Err
	}
	return "", nil
}

// RunSilent implements platform.Runner.
func (f *Fake) RunSilent(ctx context.Context, name string, args ...string) error {
	_, err := f.Run(ctx, name, args...)
	return err
}

// Calls returns every recorded command line in order.
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// Reset forgets the recorded calls.
func (f *Fake) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}
