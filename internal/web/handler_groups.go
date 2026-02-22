package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/guras256/keenetic-split-tunnel/internal/group"
	"github.com/guras256/keenetic-split-tunnel/internal/web/templates"
)

func (s *Server) handleGroupsPage(w http.ResponseWriter, r *http.Request) {
	groups, err := s.Groups.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	templates.GroupsPage(groups).Render(r.Context(), w)
}

func (s *Server) handleGroupDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	g, err := s.Groups.Get(name)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	templates.GroupCard(*g).Render(r.Context(), w)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	name := r.FormValue("name")
	desc := r.FormValue("description")

	if name == "" {
		errorResponse(w, "name is required", http.StatusBadRequest)
		return
	}

	g := group.Group{
		Name:        name,
		Description: desc,
		Enabled:     true,
	}
	if err := s.Groups.Create(g); err != nil {
		errorResponse(w, err.Error(), http.StatusConflict)
		return
	}

	s.triggerMutation()
	s.renderGroupList(w, r)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Groups.Delete(name); err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	s.triggerMutation()
	toastTrigger(w, "Group deleted", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleEnableGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Groups.SetEnabled(name, true); err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	s.triggerMutation()
	s.renderGroupCard(w, r, name)
}

func (s *Server) handleDisableGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Groups.SetEnabled(name, false); err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	s.triggerMutation()
	s.renderGroupCard(w, r, name)
}

func (s *Server) handleAddEntry(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	r.ParseForm()
	value := r.FormValue("value")
	if value == "" {
		errorResponse(w, "value is required", http.StatusBadRequest)
		return
	}

	if err := s.Groups.AddEntry(name, value); err != nil {
		errorResponse(w, err.Error(), http.StatusConflict)
		return
	}

	s.triggerMutation()
	s.renderGroupCard(w, r, name)
}

func (s *Server) handleDeleteEntry(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	value := r.PathValue("value")

	if err := s.Groups.RemoveEntry(name, value); err != nil {
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

	var added int
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := s.Groups.AddEntry(name, line); err == nil {
			added++
		}
	}

	s.triggerMutation()
	toastTrigger(w, fmt.Sprintf("%d entries added", added), "success")
	s.renderGroupCard(w, r, name)
}

func (s *Server) handleExportGroups(w http.ResponseWriter, r *http.Request) {
	data, err := s.Groups.ExportAll()
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", "attachment; filename=kst-groups.yaml")
	w.Write(data)
}

func (s *Server) handleImportGroups(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(1 << 20) // 1 MB limit
	raw := r.FormValue("body")
	if raw == "" {
		errorResponse(w, "empty import data", http.StatusBadRequest)
		return
	}
	if err := s.Groups.ImportGroups([]byte(raw)); err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.triggerMutation()
	toastTrigger(w, "Groups imported", "success")
	s.renderGroupList(w, r)
}

func (s *Server) renderGroupList(w http.ResponseWriter, r *http.Request) {
	groups, _ := s.Groups.List()
	templates.GroupList(groups).Render(r.Context(), w)
}

func (s *Server) renderGroupCard(w http.ResponseWriter, r *http.Request, name string) {
	g, err := s.Groups.Get(name)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	templates.GroupCard(*g).Render(r.Context(), w)
}

func (s *Server) renderEntryList(w http.ResponseWriter, r *http.Request, name string) {
	g, err := s.Groups.Get(name)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	templates.EntryList(name, g.Entries).Render(r.Context(), w)
}
