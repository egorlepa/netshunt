package service

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/guras256/keenetic-split-tunnel/internal/platform"
)

// Service represents an init.d managed service.
type Service struct {
	Name       string // e.g., "dnsmasq"
	InitScript string // e.g., "/opt/etc/init.d/S56dnsmasq"
}

// Common services on Keenetic with Entware.
var (
	Dnsmasq     = Service{Name: "dnsmasq", InitScript: "/opt/etc/init.d/S56dnsmasq"}
	DNSCrypt    = Service{Name: "dnscrypt-proxy2", InitScript: "/opt/etc/init.d/S09dnscrypt-proxy2"}
	Shadowsocks = Service{Name: "ss-redir", InitScript: "/opt/etc/init.d/S22shadowsocks-libev-ss-redir"}
)

// IsInstalled checks if the init script exists.
func (s Service) IsInstalled() bool {
	_, err := os.Stat(s.InitScript)
	return err == nil
}

// Start starts the service.
func (s Service) Start(ctx context.Context) error {
	if !s.IsInstalled() {
		return fmt.Errorf("service %s not installed", s.Name)
	}
	return platform.RunSilent(ctx, s.InitScript, "start")
}

// Stop stops the service.
func (s Service) Stop(ctx context.Context) error {
	if !s.IsInstalled() {
		return nil
	}
	return platform.RunSilent(ctx, s.InitScript, "stop")
}

// Restart restarts the service.
func (s Service) Restart(ctx context.Context) error {
	if !s.IsInstalled() {
		return fmt.Errorf("service %s not installed", s.Name)
	}
	return platform.RunSilent(ctx, s.InitScript, "restart")
}

// IsRunning checks if the service process is active.
func (s Service) IsRunning(ctx context.Context) bool {
	out, err := platform.Run(ctx, "pidof", s.Name)
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) != ""
}
