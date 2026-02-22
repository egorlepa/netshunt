package dns

import (
	"context"

	"github.com/egorlepa/netshunt/internal/service"
)

// DNSCrypt manages dnscrypt-proxy2 service.
type DNSCrypt struct{}

// NewDNSCrypt creates a DNSCrypt manager.
func NewDNSCrypt() *DNSCrypt {
	return &DNSCrypt{}
}

// IsInstalled returns true if dnscrypt-proxy2 init script exists.
func (d *DNSCrypt) IsInstalled() bool {
	return service.DNSCrypt.IsInstalled()
}

// IsRunning returns true if the dnscrypt-proxy2 process is active.
func (d *DNSCrypt) IsRunning(ctx context.Context) bool {
	return service.DNSCrypt.IsRunning(ctx)
}

// Enable starts dnscrypt-proxy2.
func (d *DNSCrypt) Enable(ctx context.Context) error {
	return service.DNSCrypt.Start(ctx)
}

// Disable stops dnscrypt-proxy2.
func (d *DNSCrypt) Disable(ctx context.Context) error {
	return service.DNSCrypt.Stop(ctx)
}
