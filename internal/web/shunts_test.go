package web

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/shunt"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

type countingReconciler struct{ mutations int }

func (c *countingReconciler) Reconcile(context.Context) error      { return nil }
func (c *countingReconciler) ApplyMutation(context.Context) error  { c.mutations++; return nil }
func (c *countingReconciler) ApplyBlocklist(context.Context) error { return nil }

func newShuntsTestServer(t *testing.T) (*Server, *shunt.Store, *countingReconciler) {
	t.Helper()
	store := shunt.NewStore(filepath.Join(t.TempDir(), "shunts.yaml"))
	if err := store.Create(shunt.Shunt{Name: "T", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rec := &countingReconciler{}
	cfg := config.Defaults()
	return NewServer(config.NewLive(&cfg), store, nil, nil, nil, rec, nil, nil, slog.New(slog.DiscardHandler), "test"), store, rec
}

func post(t *testing.T, s *Server, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func toast(t *testing.T, rec *httptest.ResponseRecorder) (msg, typ string) {
	t.Helper()
	var v struct {
		ShowToast struct{ Message, Type string } `json:"showToast"`
	}
	if err := json.Unmarshal([]byte(rec.Header().Get("HX-Trigger")), &v); err != nil {
		t.Fatalf("HX-Trigger %q: %v", rec.Header().Get("HX-Trigger"), err)
	}
	return v.ShowToast.Message, v.ShowToast.Type
}

func TestAddEntryRejectsInvalidWith400(t *testing.T) {
	s, store, rec := newShuntsTestServer(t)
	for _, v := range []string{"regexp:(", "2001:db8::1", "2001:db8::/32", "bad domain", "  "} {
		resp := post(t, s, "/shunts/T/entries", url.Values{"value": {v}})
		if resp.Code != http.StatusBadRequest {
			t.Errorf("%q: status %d, want 400", v, resp.Code)
			continue
		}
		if msg, typ := toast(t, resp); typ != "error" || msg == "" {
			t.Errorf("%q: toast %q/%q", v, msg, typ)
		}
	}
	sh, _ := store.Get("T")
	if len(sh.Entries) != 0 || rec.mutations != 0 {
		t.Fatalf("entries %+v, mutations %d", sh.Entries, rec.mutations)
	}
	if resp := post(t, s, "/shunts/T/entries", url.Values{"value": {"example.com"}}); resp.Code != http.StatusOK {
		t.Fatalf("valid entry: status %d", resp.Code)
	}
	if resp := post(t, s, "/shunts/T/entries", url.Values{"value": {"example.com"}}); resp.Code != http.StatusConflict {
		t.Fatalf("duplicate: status %d, want 409", resp.Code)
	}
}

func TestBulkAddNamesRejectedLines(t *testing.T) {
	s, store, rec := newShuntsTestServer(t)
	resp := post(t, s, "/shunts/T/entries/bulk", url.Values{"values": {"a.com\nregexp:(\n1.2.3.4\n\n2001:db8::1\nkeyword:x\n"}})
	if resp.Code != http.StatusOK {
		t.Fatalf("status %d", resp.Code)
	}
	msg, typ := toast(t, resp)
	if typ != "error" || !strings.Contains(msg, "3 entries added") || !strings.Contains(msg, `"regexp:("`) || !strings.Contains(msg, `"2001:db8::1"`) {
		t.Fatalf("toast %q/%q", msg, typ)
	}
	sh, _ := store.Get("T")
	if len(sh.Entries) != 3 || rec.mutations != 1 {
		t.Fatalf("entries %+v, mutations %d", sh.Entries, rec.mutations)
	}
}

func TestShuntCardMarksInvalidEntry(t *testing.T) {
	s, store, _ := newShuntsTestServer(t)
	_ = store.Update(shunt.Shunt{Name: "T", Enabled: true, Entries: []shunt.Entry{{Value: "ok.com"}, {Value: "regexp:("}}})
	req := httptest.NewRequest(http.MethodGet, "/shunts/T", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	body := rec.Body.String()
	if strings.Count(body, "not applied") != 1 {
		t.Fatalf("want one 'not applied' badge:\n%s", body)
	}
}

func put(t *testing.T, s *Server, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func shuntNames(t *testing.T, store *shunt.Store) string {
	t.Helper()
	list, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, sh := range list {
		out = append(out, sh.Name)
	}
	return strings.Join(out, ",")
}

func TestShuntsPageMarkup(t *testing.T) {
	s, store, _, _, _ := newGeositeTestServer(t)
	_ = store.Create(shunt.Shunt{Name: "off duty", Description: "Disabled one", Entries: []shunt.Entry{{Value: "b.example.org"}, {Value: "10.0.0.0/8"}}})
	if err := store.AddGeositeShunt("NETFLIX", "geosite:netflix"); err != nil {
		t.Fatal(err)
	}
	resp := do(t, s, http.MethodGet, "/shunts")
	if resp.Code != http.StatusOK {
		t.Fatalf("status %d", resp.Code)
	}
	body := resp.Body.String()
	for _, want := range []string{
		`<script src="/static/shunts.js">`,
		`id="q" type="search"`,
		`id="shunt-list"`,
		`<b id="n-on">2</b> of <b id="n-all">3</b> enabled`,
		`<b id="n-entries">6</b> entries`, // 1 + 2 + 3 valid geosite entries
		// rows in file order, with their ids and names
		`id="shunt-` + templates.SlugID("manual") + `" class="row on"`,
		`id="shunt-` + templates.SlugID("off duty") + `" class="row" data-name="off duty" data-desc="Disabled one"`,
		`id="shunt-` + templates.SlugID("NETFLIX") + `" class="row on" data-name="NETFLIX" data-desc="" data-source="geosite:netflix"`,
		`data-act="drag"`,
		// manual entries inline as removable chips
		`class="chip" data-v="10.0.0.0/8"`,
		`hx-delete="/shunts/off%20duty/entries/10.0.0.0%2F8"`,
		`hx-post="/shunts/off%20duty/entries/bulk"`,
		// rename/description form and delete
		`hx-put="/shunts/off%20duty" hx-trigger="change, submit"`,
		`hx-delete="/shunts/off%20duty"`,
		`<b data-role="pos">2 of 3</b>`,
		// geosite: lazy read-only chips, source shown when there is no description
		`class="chips ro"`,
		`hx-get="/shunts/NETFLIX/entries"`,
		`<span class="muted desc src">geosite:netflix</span>`,
		`>geosite</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	// Every server-rendered checkbox opts out of form-state restoration.
	if n, off := strings.Count(body, `type="checkbox"`), strings.Count(body, `type="checkbox" autocomplete="off"`); n != off || n != 4 { // nav + 3 toggles
		t.Errorf("checkboxes %d, with autocomplete=off %d", n, off)
	}
	if strings.Index(body, `data-name="manual"`) > strings.Index(body, `data-name="off duty"`) {
		t.Error("rows not in file order")
	}
	if strings.Contains(body, `class="row on open"`) || strings.Contains(body, `class="row open"`) {
		t.Error("row rendered expanded")
	}

	js := do(t, s, http.MethodGet, "/static/shunts.js")
	if js.Code != http.StatusOK || !strings.Contains(js.Body.String(), "/shunts/order") {
		t.Fatalf("shunts.js: %d", js.Code)
	}
}

func TestReorderShuntsEndpoint(t *testing.T) {
	s, store, rec := newShuntsTestServer(t)
	_ = store.Create(shunt.Shunt{Name: "B"})
	_ = store.Create(shunt.Shunt{Name: "C d"})

	resp := put(t, s, "/shunts/order", url.Values{"names": {"C d", "T", "B"}})
	if resp.Code != http.StatusNoContent {
		t.Fatalf("status %d", resp.Code)
	}
	if got := shuntNames(t, store); got != "C d,T,B" {
		t.Fatalf("order %s", got)
	}
	// The page renders the new order.
	body := do(t, s, http.MethodGet, "/shunts").Body.String()
	c, tt, b := strings.Index(body, `data-name="C d"`), strings.Index(body, `data-name="T"`), strings.Index(body, `data-name="B"`)
	if c > tt || tt > b {
		t.Fatal("page not in the new order")
	}

	for _, bad := range []url.Values{
		{"names": {"C d", "T"}},
		{"names": {"C d", "T", "T"}},
		{"names": {"C d", "T", "X"}},
		{},
	} {
		resp := put(t, s, "/shunts/order", bad)
		if resp.Code != http.StatusBadRequest {
			t.Errorf("%v: status %d, want 400", bad, resp.Code)
			continue
		}
		if _, typ := toast(t, resp); typ != "error" {
			t.Errorf("%v: toast type %q", bad, typ)
		}
	}
	if got := shuntNames(t, store); got != "C d,T,B" {
		t.Fatalf("order after bad requests %s", got)
	}
	if rec.mutations != 0 {
		t.Fatalf("reorder ran %d mutations", rec.mutations)
	}
}

func TestUpdateShuntEndpoint(t *testing.T) {
	s, store, rec := newShuntsTestServer(t)
	_ = store.AddEntry("T", "a.com")
	_ = store.Create(shunt.Shunt{Name: "Other"})

	resp := put(t, s, "/shunts/T", url.Values{"name": {" New name "}, "description": {"Desc"}})
	if resp.Code != http.StatusOK {
		t.Fatalf("status %d", resp.Code)
	}
	body := resp.Body.String()
	// The row comes back expanded, with every path on the new name.
	for _, want := range []string{
		`id="shunt-` + templates.SlugID("New name") + `" class="row on open"`,
		`hx-put="/shunts/New%20name"`,
		`hx-post="/shunts/New%20name/entries/bulk"`,
		`hx-delete="/shunts/New%20name/entries/a.com"`,
		`hx-put="/shunts/New%20name/disable"`,
		`<b data-role="pos">1 of 2</b>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("row lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, `/shunts/T`) {
		t.Error("row still uses the old path")
	}
	if msg, typ := toast(t, resp); typ != "success" || !strings.Contains(msg, "New name") {
		t.Errorf("toast %q/%q", msg, typ)
	}
	sh, err := store.Get("New name")
	if err != nil || sh.Description != "Desc" || len(sh.Entries) != 1 || !sh.Enabled {
		t.Fatalf("shunt %+v, %v", sh, err)
	}

	// Description only: the name field left out keeps the name.
	if resp := put(t, s, "/shunts/New%20name", url.Values{"description": {""}}); resp.Code != http.StatusOK {
		t.Fatalf("description only: %d", resp.Code)
	}
	if sh, _ := store.Get("New name"); sh == nil || sh.Description != "" {
		t.Fatalf("description not cleared: %+v", sh)
	}

	for _, tc := range []struct {
		path string
		form url.Values
		code int
	}{
		{"/shunts/New%20name", url.Values{"name": {"Other"}}, http.StatusConflict},
		{"/shunts/New%20name", url.Values{"name": {"  "}}, http.StatusBadRequest},
		{"/shunts/nope", url.Values{"name": {"x"}}, http.StatusNotFound},
	} {
		resp := put(t, s, tc.path, tc.form)
		if resp.Code != tc.code {
			t.Errorf("%s %v: status %d, want %d", tc.path, tc.form, resp.Code, tc.code)
			continue
		}
		if resp.Header().Get("HX-Retarget") != "none" {
			t.Errorf("%s %v: error would replace the row", tc.path, tc.form)
		}
	}
	if got := shuntNames(t, store); got != "New name,Other" {
		t.Fatalf("shunts %s", got)
	}
	if rec.mutations != 0 {
		t.Fatalf("rename ran %d mutations", rec.mutations)
	}
}

func TestBulkAddSplitsCommasButNotRegexps(t *testing.T) {
	s, store, _ := newShuntsTestServer(t)
	resp := post(t, s, "/shunts/T/entries/bulk", url.Values{"values": {"a.com, b.com,1.2.3.4\nregexp:^x{1,3}\\.com$\n"}})
	if resp.Code != http.StatusOK {
		t.Fatalf("status %d", resp.Code)
	}
	sh, _ := store.Get("T")
	var got []string
	for _, e := range sh.Entries {
		got = append(got, e.Value)
	}
	if strings.Join(got, " ") != `a.com b.com 1.2.3.4 regexp:^x{1,3}\.com$` {
		t.Fatalf("entries %q", got)
	}
	// The answer is the whole row, expanded.
	if !strings.Contains(resp.Body.String(), `class="row on open"`) {
		t.Fatalf("row:\n%s", resp.Body.String())
	}
}

func TestDeleteEntryUpdatesCounts(t *testing.T) {
	s, store, rec := newShuntsTestServer(t)
	_, _ = store.AddEntries("T", []string{"a.com", "b.com"})
	resp := do(t, s, http.MethodDelete, "/shunts/T/entries/a.com")
	if resp.Code != http.StatusOK || rec.mutations != 1 {
		t.Fatalf("status %d, mutations %d", resp.Code, rec.mutations)
	}
	body := resp.Body.String()
	slug := templates.SlugID("T")
	for _, want := range []string{
		`data-v="b.com"`,
		`id="count-` + slug + `" data-n="1" hx-swap-oob="true"`,
		`id="kvcount-` + slug + `" hx-swap-oob="true"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("response lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, `data-v="a.com"`) {
		t.Error("removed entry still listed")
	}
}
