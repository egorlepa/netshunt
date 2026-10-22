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
	members := -1
	if s.Tracker != nil {
		members = s.Tracker.Members()
	}
	s.render(r, w, templates.ShuntsPage(templates.ShuntsPageData{
		Shunts:       s.shuntViews(shunts),
		IPSetMembers: members,
	}))
}

// shuntViews pairs each shunt with the entry count it applies, its position
// and, for a geosite shunt without data, the reason.
func (s *Server) shuntViews(shunts []shunt.Shunt) []templates.ShuntView {
	views := make([]templates.ShuntView, len(shunts))
	for i, sh := range shunts {
		views[i] = s.shuntView(sh, i, len(shunts))
	}
	return views
}

func (s *Server) shuntView(sh shunt.Shunt, pos, total int) templates.ShuntView {
	n, ok := s.Shunts.EntryCount(sh)
	v := templates.ShuntView{Shunt: sh, Count: n, Pos: pos, Total: total}
	if !ok {
		v.NoData = s.geositeNoData()
	}
	return v
}

// geositeNoData names why a geosite shunt has no entries.
func (s *Server) geositeNoData() string {
	if s.Geosite == nil || !s.Geosite.FileInfo().Downloaded {
		return "database not downloaded"
	}
	return "category not in database"
}

// handleShuntEntries renders a shunt's entry list; for a geosite shunt it is
// the read-only list from the database, loaded when the card is expanded.
func (s *Server) handleShuntEntries(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	sh, err := s.Shunts.Get(name)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	if !sh.IsGeosite() {
		s.render(r, w, templates.EntryChips(templates.SlugID(name), name, sh.Entries, false))
		return
	}
	entries, ok := s.Shunts.Entries(*sh)
	noData := ""
	if !ok {
		noData = s.geositeNoData()
	}
	s.render(r, w, templates.GeositeEntryList(templates.SlugID(name), name, entries, noData))
}

func (s *Server) handleShuntDetail(w http.ResponseWriter, r *http.Request) {
	s.renderShuntRow(w, r, r.PathValue("name"), false)
}

// handleUpdateShunt renames a shunt and/or sets its description (form fields
// name and description; a field left out keeps its value) and answers with
// the row, expanded, since the edit comes from its open panel. The name is
// not part of what is applied (entries are), so no mutation runs.
func (s *Server) handleUpdateShunt(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	sh, err := s.Shunts.Get(name)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	newName, desc := sh.Name, sh.Description
	if _, ok := r.Form["name"]; ok {
		newName = strings.TrimSpace(r.FormValue("name"))
		if newName == "" {
			errorResponse(w, "name is required", http.StatusBadRequest)
			return
		}
	}
	if _, ok := r.Form["description"]; ok {
		desc = r.FormValue("description")
	}
	if err := s.Shunts.UpdateInfo(name, newName, desc); err != nil {
		code := http.StatusInternalServerError
		switch {
		case errors.Is(err, shunt.ErrShuntExists):
			code = http.StatusConflict
		case errors.Is(err, shunt.ErrShuntNotFound):
			code = http.StatusNotFound
		}
		errorResponse(w, err.Error(), code)
		return
	}
	msg := "Description saved"
	if newName != name {
		msg = fmt.Sprintf("Renamed to %s", newName)
	}
	toastTrigger(w, msg, "success")
	s.renderShuntRow(w, r, newName, true)
}

// handleReorderShunts stores a new shunt order: form field names, repeated,
// listing every shunt once. 204 on success, 400 when the names are not
// exactly the stored shunts. The order does not affect matching, so no
// mutation runs.
func (s *Server) handleReorderShunts(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Shunts.Reorder(r.Form["names"]); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, shunt.ErrOrderMismatch) {
			code = http.StatusBadRequest
		}
		errorResponse(w, err.Error(), code)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	s.renderShuntRow(w, r, name, true)
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

	res, err := s.Shunts.AddEntries(name, splitEntries(raw))
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
	s.renderShuntRow(w, r, name, true)
}

// splitEntries splits the add-entries text into values: one per line, and
// within a line separated by commas, except for a regexp: line, where a comma
// belongs to the pattern (a{1,3}).
func splitEntries(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, shunt.PrefixRegexp) {
			out = append(out, line)
			continue
		}
		for _, v := range strings.Split(line, ",") {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
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
	s.render(r, w, templates.ShuntList(s.shuntViews(shunts)))
}

// renderShuntRow renders one row; open renders it expanded.
func (s *Server) renderShuntRow(w http.ResponseWriter, r *http.Request, name string, open bool) {
	shunts, err := s.Shunts.List()
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for i, sh := range shunts {
		if sh.Name == name {
			v := s.shuntView(sh, i, len(shunts))
			v.Open = open
			s.render(r, w, templates.ShuntRow(v))
			return
		}
	}
	errorResponse(w, fmt.Sprintf("shunt %q not found", name), http.StatusNotFound)
}

func (s *Server) renderEntryList(w http.ResponseWriter, r *http.Request, name string) {
	sh, err := s.Shunts.Get(name)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	s.render(r, w, templates.EntryChipsUpdate(templates.SlugID(name), name, sh.Entries))
}
