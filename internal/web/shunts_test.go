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
)

type countingReconciler struct{ mutations int }

func (c *countingReconciler) Reconcile(context.Context) error      { return nil }
func (c *countingReconciler) ApplyMutation(context.Context) error  { c.mutations++; return nil }
func (c *countingReconciler) ApplyBlocklist(context.Context) error { return nil }
func (c *countingReconciler) SwitchProxy(context.Context) error    { return nil }

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
