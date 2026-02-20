package platform

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

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
