package web

import (
	"fmt"
	"net/http"

	"github.com/egorlepa/netshunt/internal/blocklist"
	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

func (s *Server) handleBlocklistPage(w http.ResponseWriter, r *http.Request) {
	s.render(r, w, templates.BlocklistPage(s.Config.Blocklist.Enabled, s.Config.Blocklist.Response, s.blocklistSourceViews()))
}

func (s *Server) handleBlocklistToggleEnabled(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	enabled := r.FormValue("enabled") != ""

	cfg, err := config.Load()
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg.Blocklist.Enabled = enabled
	if err := config.Save(cfg); err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	*s.Config = *cfg

	if err := s.Reconciler.ApplyBlocklist(r.Context()); err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if enabled {
		toastTrigger(w, "Blocklist enabled", "success")
	} else {
		toastTrigger(w, "Blocklist disabled", "success")
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBlocklistResponse(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp := config.BlocklistResponse(r.FormValue("response"))
	switch resp {
	case config.BlocklistResponseNXDomain, config.BlocklistResponseNoData, config.BlocklistResponseZero:
	default:
		errorResponse(w, "invalid response type", http.StatusBadRequest)
		return
	}

	cfg, err := config.Load()
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg.Blocklist.Response = resp
	if err := config.Save(cfg); err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	*s.Config = *cfg

	if err := s.Reconciler.ApplyBlocklist(r.Context()); err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	toastTrigger(w, "Block response updated", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBlocklistSourceToggle(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	// htmx sends "enabled=on" when checked; omits the field when unchecked.
	enabled := r.FormValue("enabled") == "on"

	if err := s.Blocklist.SetEnabled(id, enabled); err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Reconciler.ApplyBlocklist(r.Context()); err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBlocklistSourceUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	preset := blocklist.PresetByID(id)
	if preset == nil {
		errorResponse(w, "unknown source", http.StatusNotFound)
		return
	}

	count, unchanged, err := s.fetchAndRecord(r, *preset)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.Reconciler.ApplyBlocklist(r.Context()); err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	st, _ := s.Blocklist.State(id)
	msg := fmt.Sprintf("%s updated (%d domains)", preset.Name, count)
	if unchanged {
		msg = fmt.Sprintf("%s unchanged (%d domains)", preset.Name, count)
	}
	toastTrigger(w, msg, "success")
	s.render(r, w, templates.BlocklistSourceRow(templates.SourceView{Preset: *preset, State: st}))
}

func (s *Server) handleBlocklistUpdateAll(w http.ResponseWriter, r *http.Request) {
	// Fetches are run sequentially. On routers, parallel downloads spike
	// flash writes + memory pressure from simultaneous in-flight tmp files
	// and HTTP buffers without any real speedup on a single CPU core.
	var success, failed int
	for _, st := range s.Blocklist.States() {
		if !st.Enabled {
			continue
		}
		preset := blocklist.PresetByID(st.ID)
		if preset == nil {
			continue
		}
		if _, _, err := s.fetchAndRecord(r, *preset); err != nil {
			failed++
			continue
		}
		success++
	}

	if err := s.Reconciler.ApplyBlocklist(r.Context()); err != nil {
		s.Logger.Warn("apply blocklist after update", "error", err)
	}

	if failed == 0 {
		toastTrigger(w, fmt.Sprintf("Updated %d source(s)", success), "success")
	} else {
		toastTrigger(w, fmt.Sprintf("Updated %d, %d failed", success, failed), "error")
	}
	s.render(r, w, templates.BlocklistContent(s.Config.Blocklist.Enabled, s.Config.Blocklist.Response, s.blocklistSourceViews()))
}

// fetchAndRecord downloads a single source (conditional GET via stored
// validators) and records the result on the store. Returns the post-fetch
// domain count, a flag indicating the upstream returned 304 Not Modified, and
// any fatal error.
func (s *Server) fetchAndRecord(r *http.Request, preset blocklist.Source) (int, bool, error) {
	dest := blocklist.CachePath(s.Blocklist.CacheDir(), preset.ID)

	prev, _ := s.Blocklist.State(preset.ID)
	res, err := blocklist.Download(r.Context(), preset, dest, prev.ETag, prev.LastModified)
	if err != nil {
		_ = s.Blocklist.RecordError(preset.ID, err.Error())
		return 0, false, fmt.Errorf("%s: %w", preset.ID, err)
	}

	if res.NotModified {
		if err := s.Blocklist.RecordUnchanged(preset.ID); err != nil {
			return 0, false, err
		}
		return prev.DomainCount, true, nil
	}

	// Stream-count: visit each domain without building a slice so a large
	// file (1M lines) doesn't spike memory just to get a count for display.
	count := 0
	if err := blocklist.StreamFile(dest, preset.Format, func([]byte) { count++ }); err != nil {
		_ = s.Blocklist.RecordError(preset.ID, err.Error())
		return 0, false, fmt.Errorf("%s parse: %w", preset.ID, err)
	}
	if err := s.Blocklist.RecordFetch(preset.ID, count, res.ETag, res.LastModified); err != nil {
		return 0, false, err
	}
	return count, false, nil
}

// blocklistSourceViews zips Presets with persisted state in display order.
func (s *Server) blocklistSourceViews() []templates.SourceView {
	states := s.Blocklist.States()
	stateByID := make(map[string]blocklist.SourceState, len(states))
	for _, st := range states {
		stateByID[st.ID] = st
	}
	out := make([]templates.SourceView, 0, len(blocklist.Presets))
	for _, p := range blocklist.Presets {
		out = append(out, templates.SourceView{Preset: p, State: stateByID[p.ID]})
	}
	return out
}
