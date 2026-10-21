package dns

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// trackerFileVersion is the format version of the persisted tracker state.
const trackerFileVersion = 1

// trackerFile is the on-disk tracker state: the domain -> IPs map. Static
// entries are not stored, they are rebuilt from the shunts.
//
//	{"version":1,"domains":{"www.example.net":["198.51.100.1"]}}
type trackerFile struct {
	Version int                 `json:"version"`
	Domains map[string][]string `json:"domains"`
}

// persister writes the tracker state to path at most once per interval.
type persister struct {
	path     string
	interval time.Duration

	mu    sync.Mutex
	timer *time.Timer // pending debounced write, nil when none

	writeMu sync.Mutex // serialises file writes (timer vs. Save)
	writes  atomic.Int64
}

// EnablePersistence makes the tracker save its domain -> IPs map to path
// after every change, debounced: the first change schedules one write
// interval later, and changes until then ride along. Save writes at once
// (daemon shutdown). Call before the tracker is used.
func (t *Tracker) EnablePersistence(path string, interval time.Duration) {
	t.persist = &persister{path: path, interval: interval}
}

// markDirty schedules a debounced save. Called with t.mu held (the persister
// has its own lock and never takes t.mu while holding it).
func (t *Tracker) markDirty() {
	p := t.persist
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.timer != nil {
		return // a write is already scheduled and will see this change
	}
	p.timer = time.AfterFunc(p.interval, func() {
		p.mu.Lock()
		p.timer = nil
		p.mu.Unlock()
		if err := t.write(); err != nil {
			t.logger.Warn("tracker: save state failed", "path", p.path, "error", err)
		}
	})
}

// Save cancels a pending debounced write and writes the state now. A no-op
// without persistence.
func (t *Tracker) Save() error {
	p := t.persist
	if p == nil {
		return nil
	}
	p.mu.Lock()
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	p.mu.Unlock()
	return t.write()
}

// write snapshots the domain map and replaces the file atomically (temp file
// in the same directory, fsync, rename).
func (t *Tracker) write() error {
	p := t.persist
	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	t.mu.RLock()
	state := trackerFile{Version: trackerFileVersion, Domains: make(map[string][]string, len(t.forward))}
	for d, ips := range t.forward {
		state.Domains[d] = append([]string(nil), ips...)
	}
	t.mu.RUnlock()

	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, filepath.Base(p.path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	p.writes.Add(1)
	return nil
}

// LoadResult describes what LoadPersisted installed.
type LoadResult struct {
	Domains int // domains kept (matched by the current rules)
	IPs     int // distinct IPs they reference
	Dropped int // domains no current rule matches
}

// LoadPersisted reads the saved state and installs every domain match
// accepts into the maps WITHOUT exec: the members are believed to be in the
// kernel already (they are after a daemon restart; after a reboot the set
// is empty). The caller must run Repair afterwards, which re-adds what the
// kernel lacks and deletes what nothing explains. The file is input, never
// a source of truth: domains the current rules do not match are dropped,
// unparsable IPs skipped. A missing file is an empty state with a nil
// error; a corrupt one is an empty state with an error. Call on an empty
// tracker before DNS traffic starts.
func (t *Tracker) LoadPersisted(match func(domain string) bool) (LoadResult, error) {
	var res LoadResult
	p := t.persist
	if p == nil {
		return res, nil
	}
	data, err := os.ReadFile(p.path)
	if errors.Is(err, fs.ErrNotExist) {
		return res, nil
	}
	if err != nil {
		return res, err
	}
	var state trackerFile
	if err := json.Unmarshal(data, &state); err != nil {
		return res, fmt.Errorf("parse %s: %w", p.path, err)
	}
	if state.Version != trackerFileVersion {
		return res, fmt.Errorf("%s: unsupported version %d", p.path, state.Version)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	for domain, ips := range state.Domains {
		if !match(domain) {
			res.Dropped++
			continue
		}
		kept := false
		for _, ip := range ips {
			m, ok := canonicalMember(ip)
			if !ok {
				continue
			}
			t.linkLocked(domain, m)
			kept = true
		}
		if kept {
			res.Domains++
		}
	}
	res.IPs = len(t.reverse)
	return res, nil
}
