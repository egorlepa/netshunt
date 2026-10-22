package platform

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Runner executes external commands. The netfilter wrappers and the tracker
// take one so tests can substitute a fake that records every command and
// returns scripted output instead of exec'ing iptables/ipset/conntrack.
type Runner interface {
	// Run executes a command and returns its trimmed stdout. On failure the
	// error carries stderr.
	Run(ctx context.Context, name string, args ...string) (string, error)
	// RunSilent executes a command and only reports whether it failed.
	RunSilent(ctx context.Context, name string, args ...string) error
	// RunInput executes a command with stdin fed from input and returns its
	// trimmed stdout. Used for batch commands such as `ipset restore`.
	RunInput(ctx context.Context, input string, name string, args ...string) (string, error)
}

// ExecRunner is the Runner that spawns real processes.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	return Run(ctx, name, args...)
}

// RunSilent implements Runner.
func (ExecRunner) RunSilent(ctx context.Context, name string, args ...string) error {
	return RunSilent(ctx, name, args...)
}

// RunInput implements Runner.
func (ExecRunner) RunInput(ctx context.Context, input string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

// DefaultRunner is used wherever no Runner was injected.
var DefaultRunner Runner = ExecRunner{}

// OrDefault returns r, or DefaultRunner when r is nil.
func OrDefault(r Runner) Runner {
	if r == nil {
		return DefaultRunner
	}
	return r
}

// Run executes a command and returns combined stdout/stderr output.
func Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

// RunSilent executes a command and only returns an error if it fails.
func RunSilent(ctx context.Context, name string, args ...string) error {
	_, err := Run(ctx, name, args...)
	return err
}
