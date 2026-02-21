package web

import (
	"io"
	"net/http"

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
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	templates.GroupCard(*g).Render(r.Context(), w)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	name := r.FormValue("name")
	desc := r.FormValue("description")

	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	g := group.Group{
		Name:        name,
		Description: desc,
		Enabled:     true,
	}
	if err := s.Groups.Create(g); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	s.triggerMutation()
	s.renderGroupList(w, r)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Groups.Delete(name); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.triggerMutation()
	// Return empty response — htmx outerHTML swap removes the card.
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleEnableGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Groups.SetEnabled(name, true); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.triggerMutation()
	s.renderGroupCard(w, r, name)
}

func (s *Server) handleDisableGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Groups.SetEnabled(name, false); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
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
		http.Error(w, "value is required", http.StatusBadRequest)
		return
	}

	if err := s.Groups.AddEntry(name, value); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	s.triggerMutation()
	s.renderEntryList(w, r, name)
}

func (s *Server) handleDeleteEntry(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	value := r.PathValue("value")

	if err := s.Groups.RemoveEntry(name, value); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	s.triggerMutation()
	s.renderEntryList(w, r, name)
}

func (s *Server) handleImportGroups(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Groups.ImportGroups(data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.triggerMutation()
	w.WriteHeader(http.StatusOK)
}

func (s *Server) renderGroupList(w http.ResponseWriter, r *http.Request) {
	groups, _ := s.Groups.List()
	templates.GroupList(groups).Render(r.Context(), w)
}

func (s *Server) renderGroupCard(w http.ResponseWriter, r *http.Request, name string) {
	g, err := s.Groups.Get(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	templates.GroupCard(*g).Render(r.Context(), w)
}

func (s *Server) renderEntryList(w http.ResponseWriter, r *http.Request, name string) {
	g, err := s.Groups.Get(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	templates.EntryList(name, g.Entries).Render(r.Context(), w)
}
