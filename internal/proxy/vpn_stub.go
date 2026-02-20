package proxy

import (
	"context"
	"fmt"
)

// VPNStub is a placeholder for future VPN mode support (OpenVPN, WireGuard, etc.).
// It would use iptables MARK + policy routing instead of NAT REDIRECT.
type VPNStub struct{}

func (v *VPNStub) Name() string                                   { return "vpn" }
func (v *VPNStub) SetupRules(_ context.Context) error              { return fmt.Errorf("VPN mode not implemented") }
func (v *VPNStub) TeardownRules(_ context.Context) error           { return nil }
func (v *VPNStub) IsActive(_ context.Context) (bool, error)        { return false, nil }
