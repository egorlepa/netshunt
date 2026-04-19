package blocklist

// Stream invokes emit for every normalized domain from every enabled source
// cache file. Domains are yielded as byte slices that alias the scanner's
// buffer — emit must string() the slice if it intends to retain it past the
// callback.
//
// perSource, if non-nil, is called once per source after its file has been
// fully streamed, with the number of domains emitted from that source
// (pre-cross-source-dedup). Missing or unreadable cache files are skipped
// silently — updating the source will populate the cache.
//
// This is the low-memory apply path: no []string, no dedup map, no
// []shunt.Entry is built inside this call. The caller's emit closure is
// expected to insert directly into the destination data structure
// (typically the matcher's suffix map).
func (s *Store) Stream(emit func(domain []byte), perSource func(id string, count int)) {
	states := s.States()
	for _, st := range states {
		if !st.Enabled {
			continue
		}
		preset := PresetByID(st.ID)
		if preset == nil {
			continue
		}
		path := CachePath(s.CacheDir(), st.ID)
		n := 0
		wrap := func(b []byte) {
			emit(b)
			n++
		}
		_ = StreamFile(path, preset.Format, wrap)
		if perSource != nil {
			perSource(st.ID, n)
		}
	}
}
