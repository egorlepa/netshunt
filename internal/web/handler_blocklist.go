package web

import (
	"fmt"
	"net/http"
	"sync"

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

	count, err := s.fetchAndRecord(r, *preset)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.Reconciler.ApplyBlocklist(r.Context()); err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	st, _ := s.Blocklist.State(id)
	toastTrigger(w, fmt.Sprintf("%s updated (%d domains)", preset.Name, count), "success")
	s.render(r, w, templates.BlocklistSourceRow(templates.SourceView{Preset: *preset, State: st}))
}

func (s *Server) handleBlocklistUpdateAll(w http.ResponseWriter, r *http.Request) {
	states := s.Blocklist.States()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3) // cap parallel fetches

	var success, failed int
	var mu sync.Mutex

	for _, st := range states {
		if !st.Enabled {
			continue
		}
		preset := blocklist.PresetByID(st.ID)
		if preset == nil {
			continue
		}
		wg.Add(1)
		go func(p blocklist.Source) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if _, err := s.fetchAndRecord(r, p); err != nil {
				mu.Lock()
				failed++
				mu.Unlock()
				return
			}
			mu.Lock()
			success++
			mu.Unlock()
		}(*preset)
	}
	wg.Wait()

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

// fetchAndRecord downloads a single source, parses it for domain count, and
// records the result on the store.
func (s *Server) fetchAndRecord(r *http.Request, preset blocklist.Source) (int, error) {
	dest := blocklist.CachePath(s.Blocklist.CacheDir(), preset.ID)
	if err := blocklist.Download(r.Context(), preset, dest); err != nil {
		_ = s.Blocklist.RecordError(preset.ID, err.Error())
		return 0, fmt.Errorf("%s: %w", preset.ID, err)
	}
	domains, err := blocklist.Parse(dest, preset.Format)
	if err != nil {
		_ = s.Blocklist.RecordError(preset.ID, err.Error())
		return 0, fmt.Errorf("%s parse: %w", preset.ID, err)
	}
	if err := s.Blocklist.RecordFetch(preset.ID, len(domains)); err != nil {
		return 0, err
	}
	return len(domains), nil
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
