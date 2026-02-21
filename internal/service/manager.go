package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/guras256/keenetic-split-tunnel/internal/platform"
)

// Service represents an init.d managed service.
type Service struct {
	Name       string // e.g., "dnsmasq"
	InitScript string // e.g., "/opt/etc/init.d/S56dnsmasq"
	PidFile    string // optional; if set, IsRunning checks the PID file instead of pidof
}

// Common services on Keenetic with Entware.
var (
	Dnsmasq     = Service{Name: "dnsmasq", InitScript: "/opt/etc/init.d/S56dnsmasq", PidFile: platform.DnsmasqPidFile}
	DNSCrypt    = Service{Name: "dnscrypt-proxy", InitScript: "/opt/etc/init.d/S09dnscrypt-proxy2"}
	Shadowsocks = Service{Name: "ss-redir", InitScript: platform.SSRedirInitScript}
	Xray        = Service{Name: "xray", InitScript: platform.XrayInitScript}
	Daemon      = Service{Name: "kst-daemon", InitScript: platform.InitScript, PidFile: platform.PidFile}
)

const initDir = "/opt/etc/init.d"

// initScript returns the path to the init script, searching dynamically if the
// default path doesn't exist. Handles cases where Entware packages use
// different init script naming conventions.
func (s Service) initScript() string {
	if _, err := os.Stat(s.InitScript); err == nil {
		return s.InitScript
	}
	patterns := []string{
		filepath.Join(initDir, "S*"+s.Name+"*"),
		filepath.Join(initDir, "S*"+strings.ReplaceAll(s.Name, "-", "*")),
	}
	for _, pattern := range patterns {
		if matches, _ := filepath.Glob(pattern); len(matches) > 0 {
			return matches[0]
		}
	}
	return s.InitScript
}

// IsInstalled checks if the init script exists.
func (s Service) IsInstalled() bool {
	_, err := os.Stat(s.initScript())
	return err == nil
}

// Start starts the service.
func (s Service) Start(ctx context.Context) error {
	script := s.initScript()
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("service %s not installed (no init script at %s)", s.Name, script)
	}
	return platform.RunSilent(ctx, script, "start")
}

// Stop stops the service.
func (s Service) Stop(ctx context.Context) error {
	script := s.initScript()
	if _, err := os.Stat(script); err != nil {
		return nil
	}
	return platform.RunSilent(ctx, script, "stop")
}

// Restart restarts the service.
func (s Service) Restart(ctx context.Context) error {
	script := s.initScript()
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("service %s not installed (no init script at %s)", s.Name, script)
	}
	return platform.RunSilent(ctx, script, "restart")
}

// IsRunning checks if the service process is active.
// If PidFile is set, reads it and checks /proc/<pid>; otherwise uses pidof.
func (s Service) IsRunning(ctx context.Context) bool {
	if s.PidFile != "" {
		data, err := os.ReadFile(s.PidFile)
		if err != nil {
			return false
		}
		pid := strings.TrimSpace(string(data))
		_, err = os.Stat("/proc/" + pid)
		return err == nil
	}
	out, err := platform.Run(ctx, "pidof", s.Name)
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) != ""
}

// EnsureRunning starts the service if it's not already running.
func (s Service) EnsureRunning(ctx context.Context) error {
	if s.IsRunning(ctx) {
		return nil
	}
	if !s.IsInstalled() {
		return fmt.Errorf("service %s not installed", s.Name)
	}
	return s.Start(ctx)
}
