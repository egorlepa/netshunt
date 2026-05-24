package web

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/robfig/cron/v3"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/geosite"
	"github.com/egorlepa/netshunt/internal/platform"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

func (s *Server) handleGeositePage(w http.ResponseWriter, r *http.Request) {
	info, categories, imported := s.loadGeositeState()
	s.render(r, w, templates.GeositePage(info, s.Config.Geosite.AutoUpdate, categories, imported))
}

func (s *Server) handleGeositeDownload(w http.ResponseWriter, r *http.Request) {
	if err := geosite.Download(r.Context(), platform.GeositeFile); err != nil {
		errorResponse(w, "Download failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	toastTrigger(w, "Database downloaded", "success")
	info, categories, imported := s.loadGeositeState()
	s.render(r, w, templates.GeositeContent(info, s.Config.Geosite.AutoUpdate, categories, imported))
}

func (s *Server) handleGeositeUpdate(w http.ResponseWriter, r *http.Request) {
	updated, err := s.UpdateGeosite(r.Context())
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	toastTrigger(w, fmt.Sprintf("Database updated, %d shunts refreshed", updated), "success")
	info, categories, imported := s.loadGeositeState()
	s.render(r, w, templates.GeositeContent(info, s.Config.Geosite.AutoUpdate, categories, imported))
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
	*s.Config = *cfg

	if s.Scheduler != nil {
		if err := s.Scheduler.Reconfigure(); err != nil {
			errorResponse(w, "saved, but scheduler reconfigure failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	toastTrigger(w, "Auto-update settings applied", "success")
	w.WriteHeader(http.StatusOK)
}

// UpdateGeosite downloads the latest geosite database and resyncs every shunt
// sourced from it. Safe to call from a background goroutine (scheduler).
// Returns the number of shunts refreshed.
func (s *Server) UpdateGeosite(ctx context.Context) (int, error) {
	if err := geosite.Download(ctx, platform.GeositeFile); err != nil {
		return 0, fmt.Errorf("download: %w", err)
	}

	db, err := geosite.Parse(platform.GeositeFile)
	if err != nil {
		return 0, fmt.Errorf("parse: %w", err)
	}

	geositeShunts, err := s.Shunts.GeositeShunts()
	if err != nil {
		return 0, err
	}

	var updated int
	for _, sh := range geositeShunts {
		category := strings.TrimPrefix(sh.Source, "geosite:")
		domains, err := geosite.ExtractEntries(db, category)
		if err != nil {
			s.Logger.Warn("geosite category missing in update", "category", category)
			continue
		}
		if err := s.Shunts.SyncGeositeShunt(sh.Name, sh.Source, domains); err != nil {
			s.Logger.Error("failed to sync geosite shunt", "name", sh.Name, "error", err)
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

	db, err := geosite.Parse(platform.GeositeFile)
	if err != nil {
		errorResponse(w, "Failed to parse database: "+err.Error(), http.StatusInternalServerError)
		return
	}

	domains, err := geosite.ExtractEntries(db, category)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}

	source := "geosite:" + strings.ToLower(category)
	if err := s.Shunts.SyncGeositeShunt(category, source, domains); err != nil {
		errorResponse(w, err.Error(), http.StatusConflict)
		return
	}

	s.triggerMutation(r.Context())
	toastTrigger(w, fmt.Sprintf("Imported %s (%d domains)", category, len(domains)), "success")
	cat := geosite.CategoryInfo{Name: category, DomainCount: len(domains)}
	s.render(r, w, templates.GeositeCategoryRow(cat, true))
}

func (s *Server) handleGeositeRemove(w http.ResponseWriter, r *http.Request) {
	category := r.PathValue("category")
	if category == "" {
		errorResponse(w, "category is required", http.StatusBadRequest)
		return
	}

	if err := s.Shunts.Delete(category); err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}

	s.triggerMutation(r.Context())
	toastTrigger(w, fmt.Sprintf("Removed %s", category), "success")
	// Get domain count from db to render the row with correct count.
	domainCount := 0
	if db, err := geosite.Parse(platform.GeositeFile); err == nil {
		if domains, err := geosite.ExtractEntries(db, category); err == nil {
			domainCount = len(domains)
		}
	}
	cat := geosite.CategoryInfo{Name: category, DomainCount: domainCount}
	s.render(r, w, templates.GeositeCategoryRow(cat, false))
}

func (s *Server) loadGeositeState() (geosite.FileInfo, []geosite.CategoryInfo, map[string]bool) {
	var info geosite.FileInfo

	stat, err := os.Stat(platform.GeositeFile)
	if err != nil {
		return info, nil, nil
	}
	info.Downloaded = true
	info.LastModified = stat.ModTime()

	db, err := geosite.Parse(platform.GeositeFile)
	if err != nil {
		s.Logger.Error("failed to parse geosite database", "error", err)
		return info, nil, nil
	}

	categories := geosite.ListCategories(db)
	info.CategoryCount = len(categories)

	// Build set of imported categories.
	imported := make(map[string]bool)
	geositeShunts, _ := s.Shunts.GeositeShunts()
	for _, sh := range geositeShunts {
		imported[sh.Name] = true
	}

	return info, categories, imported
}
