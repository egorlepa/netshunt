package web

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/egorlepa/netshunt/internal/geosite"
	"github.com/egorlepa/netshunt/internal/platform"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

func (s *Server) handleGeositePage(w http.ResponseWriter, r *http.Request) {
	info, categories, imported := s.loadGeositeState()
	templates.GeositePage(info, categories, imported).Render(r.Context(), w)
}

func (s *Server) handleGeositeDownload(w http.ResponseWriter, r *http.Request) {
	if err := geosite.Download(r.Context(), platform.GeositeFile); err != nil {
		errorResponse(w, "Download failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	toastTrigger(w, "Database downloaded", "success")
	info, categories, imported := s.loadGeositeState()
	templates.GeositeContent(info, categories, imported).Render(r.Context(), w)
}

func (s *Server) handleGeositeUpdate(w http.ResponseWriter, r *http.Request) {
	if err := geosite.Download(r.Context(), platform.GeositeFile); err != nil {
		errorResponse(w, "Download failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	db, err := geosite.Parse(platform.GeositeFile)
	if err != nil {
		errorResponse(w, "Parse failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Refresh all geosite-sourced shunts.
	geositeShunts, err := s.Shunts.GeositeShunts()
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var updated int
	for _, sh := range geositeShunts {
		category := strings.TrimPrefix(sh.Source, "geosite:")
		domains, err := geosite.ExtractDomains(db, category)
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

	s.triggerMutation()
	toastTrigger(w, fmt.Sprintf("Database updated, %d shunts refreshed", updated), "success")
	info, categories, imported := s.loadGeositeState()
	templates.GeositeContent(info, categories, imported).Render(r.Context(), w)
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

	domains, err := geosite.ExtractDomains(db, category)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}

	source := "geosite:" + strings.ToLower(category)
	if err := s.Shunts.SyncGeositeShunt(category, source, domains); err != nil {
		errorResponse(w, err.Error(), http.StatusConflict)
		return
	}

	s.triggerMutation()
	toastTrigger(w, fmt.Sprintf("Imported %s (%d domains)", category, len(domains)), "success")
	info, categories, imported := s.loadGeositeState()
	templates.GeositeContent(info, categories, imported).Render(r.Context(), w)
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

	s.triggerMutation()
	toastTrigger(w, fmt.Sprintf("Removed %s", category), "success")
	info, categories, imported := s.loadGeositeState()
	templates.GeositeContent(info, categories, imported).Render(r.Context(), w)
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
