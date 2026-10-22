package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/robfig/cron/v3"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/geosite"
	"github.com/egorlepa/netshunt/internal/platform"
	"github.com/egorlepa/netshunt/internal/shunt"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

func (s *Server) handleGeositePage(w http.ResponseWriter, r *http.Request) {
	info, categories, imported := s.loadGeositeState()
	s.render(r, w, templates.GeositePage(info, s.Config.Load().Geosite.AutoUpdate, categories, imported))
}

func (s *Server) handleGeositeDownload(w http.ResponseWriter, r *http.Request) {
	if err := geosite.Download(r.Context(), platform.GeositeFile); err != nil {
		errorResponse(w, "Download failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Geosite shunts imported before the download (or kept from a deleted
	// database) take effect now.
	s.triggerMutation(r.Context())

	toastTrigger(w, "Database downloaded", "success")
	info, categories, imported := s.loadGeositeState()
	s.render(r, w, templates.GeositeContent(info, s.Config.Load().Geosite.AutoUpdate, categories, imported))
}

func (s *Server) handleGeositeUpdate(w http.ResponseWriter, r *http.Request) {
	updated, err := s.UpdateGeosite(r.Context())
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	toastTrigger(w, fmt.Sprintf("Database updated, %d geosite shunts applied", updated), "success")
	info, categories, imported := s.loadGeositeState()
	s.render(r, w, templates.GeositeContent(info, s.Config.Load().Geosite.AutoUpdate, categories, imported))
}

func (s *Server) handleGeositeAutoUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	enabled := r.FormValue("enabled") != ""
	schedule := strings.TrimSpace(r.FormValue("schedule"))
	if schedule == "" {
		schedule = config.DefaultGeositeSchedule
	}
	if _, err := cron.ParseStandard(schedule); err != nil {
		errorResponse(w, "invalid cron expression: "+err.Error(), http.StatusBadRequest)
		return
	}

	cfg, err := config.Load()
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg.Geosite.AutoUpdate.Enabled = enabled
	cfg.Geosite.AutoUpdate.Schedule = schedule
	if err := config.Save(cfg); err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.Config.Store(cfg)

	if s.Scheduler != nil {
		if err := s.Scheduler.Reconfigure(); err != nil {
			errorResponse(w, "saved, but scheduler reconfigure failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	toastTrigger(w, "Auto-update settings applied", "success")
	w.WriteHeader(http.StatusOK)
}

// UpdateGeosite downloads the latest geosite database and applies it.
// Geosite shunts are references, so nothing is rewritten: the index notices
// the new file by its stat and the mutation rebuilds the matcher from it
// (domains dropped from a category are swept, new ones seeded). Safe to call
// from a background goroutine (scheduler). Returns the number of geosite
// shunts that have data in the new database; the others are logged and stay.
func (s *Server) UpdateGeosite(ctx context.Context) (int, error) {
	if err := geosite.Download(ctx, platform.GeositeFile); err != nil {
		return 0, fmt.Errorf("download: %w", err)
	}

	geositeShunts, err := s.Shunts.GeositeShunts()
	if err != nil {
		return 0, err
	}

	var updated int
	for _, sh := range geositeShunts {
		category, _ := sh.GeositeCategory()
		if _, ok := s.Geosite.Entries(category); !ok {
			s.Logger.Warn("geosite category missing in update, shunt kept without entries", "shunt", sh.Name, "category", category)
			continue
		}
		updated++
	}

	s.triggerMutation(ctx)
	return updated, nil
}

func (s *Server) handleGeositeImport(w http.ResponseWriter, r *http.Request) {
	category := r.PathValue("category")
	if category == "" {
		errorResponse(w, "category is required", http.StatusBadRequest)
		return
	}

	domains, ok := s.Geosite.Entries(category)
	if !ok {
		errorResponse(w, fmt.Sprintf("category %q not found", category), http.StatusNotFound)
		return
	}

	sh := shunt.Shunt{Name: category, Source: shunt.GeositeSourcePrefix + strings.ToLower(category)}
	if err := s.Shunts.AddGeositeShunt(sh.Name, sh.Source); err != nil {
		errorResponse(w, err.Error(), http.StatusConflict)
		return
	}

	s.triggerMutation(r.Context())
	valid, _ := s.Shunts.EntryCount(sh)
	msg := fmt.Sprintf("Imported %s (%d domains)", category, valid)
	if skipped := len(domains) - valid; skipped > 0 {
		msg += fmt.Sprintf(", %d invalid not applied", skipped)
	}
	toastTrigger(w, msg, "success")
	cat := geosite.CategoryInfo{Name: category, DomainCount: len(domains)}
	s.render(r, w, templates.GeositeCategoryRow(cat, true))
}

func (s *Server) handleGeositeRemove(w http.ResponseWriter, r *http.Request) {
	category := r.PathValue("category")
	if category == "" {
		errorResponse(w, "category is required", http.StatusBadRequest)
		return
	}

	sh, err := s.Shunts.Get(category)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	if !sh.IsGeosite() {
		errorResponse(w, fmt.Sprintf("shunt %q is not a geosite shunt", category), http.StatusConflict)
		return
	}
	if err := s.Shunts.Delete(category); err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}

	s.triggerMutation(r.Context())
	toastTrigger(w, fmt.Sprintf("Removed %s", category), "success")
	domains, _ := s.Geosite.Entries(category)
	cat := geosite.CategoryInfo{Name: category, DomainCount: len(domains)}
	s.render(r, w, templates.GeositeCategoryRow(cat, false))
}

func (s *Server) loadGeositeState() (geosite.FileInfo, []geosite.CategoryInfo, map[string]bool) {
	info := s.Geosite.FileInfo()
	if !info.Downloaded {
		return info, nil, nil
	}
	categories, err := s.Geosite.Categories()
	if err != nil {
		s.Logger.Error("failed to index geosite database", "error", err)
	}

	// Build set of imported categories.
	imported := make(map[string]bool)
	geositeShunts, _ := s.Shunts.GeositeShunts()
	for _, sh := range geositeShunts {
		imported[sh.Name] = true
	}

	return info, categories, imported
}
