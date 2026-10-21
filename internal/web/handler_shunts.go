package web

import (
	"errors"
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
	s.render(r, w, templates.ShuntsPage(shunts))
}

func (s *Server) handleShuntDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	sh, err := s.Shunts.Get(name)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	s.render(r, w, templates.ShuntCard(*sh))
}

func (s *Server) handleCreateShunt(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
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

	s.triggerMutation(r.Context())
	s.renderShuntList(w, r)
}

func (s *Server) handleDeleteShunt(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Shunts.Delete(name); err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	s.triggerMutation(r.Context())
	toastTrigger(w, "Shunt deleted", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleEnableShunt(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Shunts.SetEnabled(name, true); err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	s.triggerMutation(r.Context())
	s.renderShuntToggle(w, r, name)
}

func (s *Server) handleDisableShunt(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Shunts.SetEnabled(name, false); err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	s.triggerMutation(r.Context())
	s.renderShuntToggle(w, r, name)
}

func (s *Server) handleAddEntry(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	value := r.FormValue("value")
	if strings.TrimSpace(value) == "" {
		errorResponse(w, "value is required", http.StatusBadRequest)
		return
	}

	if err := s.Shunts.AddEntry(name, value); err != nil {
		code := http.StatusConflict
		var ie *shunt.InvalidEntryError
		if errors.As(err, &ie) {
			code = http.StatusBadRequest
		}
		errorResponse(w, err.Error(), code)
		return
	}

	s.triggerMutation(r.Context())
	s.renderShuntCard(w, r, name)
}

func (s *Server) handleDeleteEntry(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	value := r.PathValue("value")

	if err := s.Shunts.RemoveEntry(name, value); err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}

	s.triggerMutation(r.Context())
	s.renderEntryList(w, r, name)
}

func (s *Server) handleBulkAddEntries(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	raw := r.FormValue("values")
	if raw == "" {
		errorResponse(w, "values is required", http.StatusBadRequest)
		return
	}

	res, err := s.Shunts.AddEntries(name, strings.Split(raw, "\n"))
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}

	if res.Added > 0 {
		s.triggerMutation(r.Context())
	}
	msg := fmt.Sprintf("%d entries added", res.Added)
	if res.Duplicates > 0 {
		msg += fmt.Sprintf(", %d already present", res.Duplicates)
	}
	typ := "success"
	if len(res.Rejected) > 0 {
		typ = "error"
		var bad []string
		for _, e := range res.Rejected {
			bad = append(bad, fmt.Sprintf("%q (%s)", e.Value, e.Reason))
		}
		msg += fmt.Sprintf(", %d rejected: %s", len(res.Rejected), strings.Join(bad, "; "))
	}
	toastTrigger(w, msg, typ)
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
	if _, err := w.Write(data); err != nil {
		s.Logger.Warn("write export response", "error", err)
	}
}

func (s *Server) handleImportShunts(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(1 << 20); err != nil { // 1 MB limit
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	raw := r.FormValue("body")
	if raw == "" {
		errorResponse(w, "empty import data", http.StatusBadRequest)
		return
	}
	if err := s.Shunts.ImportShunts([]byte(raw)); err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.triggerMutation(r.Context())
	toastTrigger(w, "Shunts imported", "success")
	s.renderShuntList(w, r)
}

func (s *Server) renderShuntToggle(w http.ResponseWriter, r *http.Request, name string) {
	sh, err := s.Shunts.Get(name)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	s.render(r, w, templates.ShuntToggle(*sh))
}

func (s *Server) renderShuntList(w http.ResponseWriter, r *http.Request) {
	shunts, _ := s.Shunts.List()
	s.render(r, w, templates.ShuntList(shunts))
}

func (s *Server) renderShuntCard(w http.ResponseWriter, r *http.Request, name string) {
	sh, err := s.Shunts.Get(name)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	s.render(r, w, templates.ShuntCard(*sh))
}

func (s *Server) renderEntryList(w http.ResponseWriter, r *http.Request, name string) {
	sh, err := s.Shunts.Get(name)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	s.render(r, w, templates.EntryList(templates.SlugID(name), name, sh.Entries, sh.Source != ""))
}
