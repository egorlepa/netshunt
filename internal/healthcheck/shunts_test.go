package healthcheck

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/egorlepa/netshunt/internal/shunt"
)

type mapProvider map[string][]string

func (m mapProvider) Entries(c string) ([]string, bool) { e, ok := m[c]; return e, ok }

func TestCheckShuntsCountsGeositeAndWarnsWithoutData(t *testing.T) {
	s := shunt.NewStore(filepath.Join(t.TempDir(), "shunts.yaml"))
	s.SetGeositeProvider(mapProvider{"g": {"domain:a.com", "domain:b.com"}})
	_ = s.Create(shunt.Shunt{Name: "M", Enabled: true, Entries: []shunt.Entry{{Value: "m.com"}}})
	_ = s.AddGeositeShunt("G", "geosite:g")

	r := checkShunts(s)
	if !r.Passed || r.Detail != "2 enabled, 3 entries" {
		t.Fatalf("result = %+v", r)
	}

	_ = s.AddGeositeShunt("zz-nocat", "geosite:zz-does-not-exist")
	r = checkShunts(s)
	if r.Passed || !r.Warn || !strings.Contains(r.Detail, "zz-nocat (geosite:zz-does-not-exist)") ||
		!strings.HasPrefix(r.Detail, "3 enabled, 3 entries;") {
		t.Fatalf("result = %+v", r)
	}

	// Disabled: not reported.
	_ = s.SetEnabled("zz-nocat", false)
	if r = checkShunts(s); !r.Passed {
		t.Fatalf("result = %+v", r)
	}
}
