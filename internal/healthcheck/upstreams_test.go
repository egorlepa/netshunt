package healthcheck

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/egorlepa/netshunt/internal/dns"
)

func TestCheckDNSUpstreams(t *testing.T) {
	ups := []dns.Upstream{
		{URL: "https://8.8.8.8/dns-query", SNI: "dns.google"},
		{URL: "https://1.1.1.1/dns-query", SNI: "cloudflare-dns.com"},
		{URL: "https://9.9.9.9/dns-query", SNI: "dns.quad9.net"},
	}
	probe := func(failing ...string) upstreamProbe {
		return func(_ context.Context, u dns.Upstream) (time.Duration, error) {
			for _, f := range failing {
				if u.SNI == f {
					return 0, errors.New("timeout")
				}
			}
			return 25 * time.Millisecond, nil
		}
	}

	r := checkDNSUpstreams(context.Background(), ups, probe())
	if !r.Passed || r.Warn || !strings.HasPrefix(r.Detail, "3/3 answering") || !strings.Contains(r.Detail, "dns.google 25ms") {
		t.Errorf("all up: %+v", r)
	}

	r = checkDNSUpstreams(context.Background(), ups, probe("dns.quad9.net"))
	if r.Passed || !r.Warn || !strings.HasPrefix(r.Detail, "2/3 answering") || !strings.Contains(r.Detail, "dns.quad9.net: timeout") {
		t.Errorf("partial: %+v", r)
	}

	r = checkDNSUpstreams(context.Background(), ups, probe("dns.google", "cloudflare-dns.com", "dns.quad9.net"))
	if r.Passed || r.Warn || !strings.HasPrefix(r.Detail, "0/3 answering") {
		t.Errorf("all down: %+v", r)
	}
}
