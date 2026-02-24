package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/egorlepa/netshunt/internal/shunt"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

func (s *Server) handleShuntsPage(w http.ResponseWriter, r *http.Request) {
	shunts, err := s.Shunts.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	templates.ShuntsPage(shunts).Render(r.Context(), w)
}

func (s *Server) handleShuntDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	sh, err := s.Shunts.Get(name)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	templates.ShuntCard(*sh).Render(r.Context(), w)
}

func (s *Server) handleCreateShunt(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	name := r.FormValue("name")
	desc := r.FormValue("description")

	if name == "" {
		errorResponse(w, "name is required", http.StatusBadRequest)
		return
	}

	sh := shunt.Shunt{
		Name:        name,
		Description: desc,
		Enabled:     true,
	}
	if err := s.Shunts.Create(sh); err != nil {
		errorResponse(w, err.Error(), http.StatusConflict)
		return
	}

	s.triggerMutation()
	s.renderShuntList(w, r)
}

func (s *Server) handleDeleteShunt(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Shunts.Delete(name); err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	s.triggerMutation()
	toastTrigger(w, "Shunt deleted", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleEnableShunt(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Shunts.SetEnabled(name, true); err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	s.triggerMutation()
	s.renderShuntCard(w, r, name)
}

func (s *Server) handleDisableShunt(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Shunts.SetEnabled(name, false); err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	s.triggerMutation()
	s.renderShuntCard(w, r, name)
}

func (s *Server) handleAddEntry(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	r.ParseForm()
	value := r.FormValue("value")
	if value == "" {
		errorResponse(w, "value is required", http.StatusBadRequest)
		return
	}

	if err := s.Shunts.AddEntry(name, value); err != nil {
		errorResponse(w, err.Error(), http.StatusConflict)
		return
	}

	s.triggerMutation()
	s.renderShuntCard(w, r, name)
}

func (s *Server) handleDeleteEntry(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	value := r.PathValue("value")

	if err := s.Shunts.RemoveEntry(name, value); err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}

	s.triggerMutation()
	s.renderEntryList(w, r, name)
}

func (s *Server) handleBulkAddEntries(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	r.ParseForm()
	raw := r.FormValue("values")
	if raw == "" {
		errorResponse(w, "values is required", http.StatusBadRequest)
		return
	}

	var added, skipped int
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := s.Shunts.AddEntry(name, line); err == nil {
			added++
		} else {
			skipped++
		}
	}

	s.triggerMutation()
	msg := fmt.Sprintf("%d entries added", added)
	if skipped > 0 {
		msg += fmt.Sprintf(", %d skipped", skipped)
	}
	toastTrigger(w, msg, "success")
	s.renderShuntCard(w, r, name)
}

func (s *Server) handleExportShunts(w http.ResponseWriter, r *http.Request) {
	data, err := s.Shunts.ExportAll()
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", "attachment; filename=netshunt-shunts.yaml")
	w.Write(data)
}

func (s *Server) handleImportShunts(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(1 << 20) // 1 MB limit
	raw := r.FormValue("body")
	if raw == "" {
		errorResponse(w, "empty import data", http.StatusBadRequest)
		return
	}
	if err := s.Shunts.ImportShunts([]byte(raw)); err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.triggerMutation()
	toastTrigger(w, "Shunts imported", "success")
	s.renderShuntList(w, r)
}

func (s *Server) renderShuntList(w http.ResponseWriter, r *http.Request) {
	shunts, _ := s.Shunts.List()
	templates.ShuntList(shunts).Render(r.Context(), w)
}

func (s *Server) renderShuntCard(w http.ResponseWriter, r *http.Request, name string) {
	sh, err := s.Shunts.Get(name)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	templates.ShuntCard(*sh).Render(r.Context(), w)
}

func (s *Server) renderEntryList(w http.ResponseWriter, r *http.Request, name string) {
	sh, err := s.Shunts.Get(name)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	templates.EntryList(templates.SlugID(name), name, sh.Entries, sh.Source != "").Render(r.Context(), w)
}
