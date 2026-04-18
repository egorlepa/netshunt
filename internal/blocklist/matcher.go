package blocklist

import (
	"os"

	"github.com/egorlepa/netshunt/internal/shunt"
)

// BuildEntries reads every enabled source's cache file, dedups across all
// sources, and returns them as suffix-match shunt entries (so "example.com"
// blocks that domain and any subdomain). Missing or unreadable cache files
// are skipped silently — updating a source populates its cache.
//
// Returns (entries, perSourceCounts). perSourceCounts maps source ID to the
// number of unique domains contributed (after cross-source dedup — a domain
// counts for the first source that provided it).
func BuildEntries(s *Store) ([]shunt.Entry, map[string]int) {
	states := s.States()
	seen := make(map[string]struct{})
	counts := make(map[string]int, len(states))
	var entries []shunt.Entry

	for _, st := range states {
		if !st.Enabled {
			continue
		}
		preset := PresetByID(st.ID)
		if preset == nil {
			continue
		}
		path := CachePath(s.CacheDir(), st.ID)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		domains, err := Parse(path, preset.Format)
		if err != nil {
			continue
		}
		for _, d := range domains {
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			entries = append(entries, shunt.Entry{Value: shunt.PrefixDomainSuffix + d})
			counts[st.ID]++
		}
	}
	return entries, counts
}
