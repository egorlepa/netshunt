package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/geosite"
	"github.com/egorlepa/netshunt/internal/shunt"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

// geositePreviewCap bounds the domains a category preview shows.
const geositePreviewCap = 500

func (s *Server) handleGeositePage(w http.ResponseWriter, r *http.Request) {
	s.render(r, w, templates.GeositePage(s.geositePageData()))
}

func (s *Server) geositePageData() templates.GeositePageData {
	info, categories, used := s.loadGeositeState()
	au := s.Config.Load().Geosite.AutoUpdate
	schedule := au.Schedule
	if schedule == "" {
		schedule = config.DefaultGeositeSchedule
	}
	return templates.GeositePageData{
		Info:         info,
		AutoEnabled:  au.Enabled,
		Schedule:     schedule,
		ScheduleText: templates.ScheduleText(schedule, au.Enabled, time.Now()),
		Categories:   categories,
		Used:         used,
	}
}

// handleGeositeEntries is the lazy preview of a category: its first
// geositePreviewCap entries.
func (s *Server) handleGeositeEntries(w http.ResponseWriter, r *http.Request) {
	entries, ok := s.Geosite.Entries(r.PathValue("category"))
	if !ok {
		errorResponse(w, fmt.Sprintf("category %q not found", r.PathValue("category")), http.StatusNotFound)
		return
	}
	s.render(r, w, templates.GeositePreview(entries[:min(len(entries), geositePreviewCap)], len(entries)))
}

func (s *Server) handleGeositeDownload(w http.ResponseWriter, r *http.Request) {
	if err := s.downloadGeosite(r.Context()); err != nil {
		errorResponse(w, "Download failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Geosite shunts imported before the download (or kept from a deleted
	// database) take effect now.
	s.triggerMutation(r.Context())

	toastTrigger(w, "Database downloaded", "success")
	s.render(r, w, templates.GeositeContent(s.geositePageData()))
}

func (s *Server) handleGeositeUpdate(w http.ResponseWriter, r *http.Request) {
	updated, err := s.UpdateGeosite(r.Context())
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	toastTrigger(w, fmt.Sprintf("Database updated, %d geosite shunts applied", updated), "success")
	s.render(r, w, templates.GeositeContent(s.geositePageData()))
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
	_, _ = io.WriteString(w, templates.ScheduleText(schedule, enabled, time.Now()))
}

// UpdateGeosite downloads the latest geosite database and applies it.
// Geosite shunts are references, so nothing is rewritten: the index notices
// the new file by its stat and the mutation rebuilds the matcher from it
// (domains dropped from a category are swept, new ones seeded). Safe to call
// from a background goroutine (scheduler). Returns the number of geosite
// shunts that have data in the new database; the others are logged and stay.
func (s *Server) UpdateGeosite(ctx context.Context) (int, error) {
	if err := s.downloadGeosite(ctx); err != nil {
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
	s.Logger.Info("geosite update applied", "geosite_shunts", len(geositeShunts), "with_data", updated)
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
	_, _, used := s.loadGeositeState()
	name := used[category]
	if name == "" {
		name = category
	}
	s.render(r, w, templates.GeositeCategoryRow(cat, name))
}

func (s *Server) handleGeositeRemove(w http.ResponseWriter, r *http.Request) {
	category := r.PathValue("category")
	if category == "" {
		errorResponse(w, "category is required", http.StatusBadRequest)
		return
	}

	// The shunt may have been renamed on the Shunts page: find it by its
	// source first, by the category name second.
	name := ""
	geositeShunts, _ := s.Shunts.GeositeShunts()
	for _, sh := range geositeShunts {
		if cat, _ := sh.GeositeCategory(); strings.EqualFold(cat, category) {
			name = sh.Name
			break
		}
	}
	if name == "" {
		sh, err := s.Shunts.Get(category)
		if err != nil {
			errorResponse(w, err.Error(), http.StatusNotFound)
			return
		}
		if !sh.IsGeosite() {
			errorResponse(w, fmt.Sprintf("shunt %q is not a geosite shunt", category), http.StatusConflict)
			return
		}
		name = sh.Name
	}
	if err := s.Shunts.Delete(name); err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}

	s.triggerMutation(r.Context())
	toastTrigger(w, fmt.Sprintf("Removed %s", category), "success")
	domains, _ := s.Geosite.Entries(category)
	cat := geosite.CategoryInfo{Name: category, DomainCount: len(domains)}
	s.render(r, w, templates.GeositeCategoryRow(cat, ""))
}

// loadGeositeState returns the database info, its categories, and for each
// category a shunt references, that shunt's name.
func (s *Server) loadGeositeState() (geosite.FileInfo, []geosite.CategoryInfo, map[string]string) {
	info := s.Geosite.FileInfo()
	if !info.Downloaded {
		return info, nil, nil
	}
	categories, err := s.Geosite.Categories()
	if err != nil {
		s.Logger.Error("failed to index geosite database", "error", err)
	}

	// Used categories, by the shunts' sources: a geosite shunt can be
	// renamed on the Shunts page. The first shunt of a category wins.
	sources := make(map[string]string)
	geositeShunts, _ := s.Shunts.GeositeShunts()
	for _, sh := range geositeShunts {
		if cat, ok := sh.GeositeCategory(); ok {
			if _, dup := sources[strings.ToLower(cat)]; !dup {
				sources[strings.ToLower(cat)] = sh.Name
			}
		}
	}
	used := make(map[string]string)
	for _, cat := range categories {
		if name, ok := sources[strings.ToLower(cat.Name)]; ok {
			used[cat.Name] = name
		}
	}

	return info, categories, used
}

// downloadGeosite fetches dlc.dat, counting a failure for the update
// metrics (the success time is the file's mtime).
func (s *Server) downloadGeosite(ctx context.Context) error {
	err := geosite.Download(ctx, s.geositeFile)
	if err != nil {
		s.geositeFailures.Inc()
	}
	return err
}
