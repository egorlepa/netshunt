package web

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/egorlepa/netshunt/internal/shunt"
)

// Entry values and shunt names with URL-special characters must survive the
// template -> htmx -> mux -> PathValue round trip.
func TestDeleteEntryWithSpecialCharacters(t *testing.T) {
	store := shunt.NewStore(filepath.Join(t.TempDir(), "shunts.yaml"))
	const name = "my shunt #1"
	if err := store.Create(shunt.Shunt{Name: name, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	values := []string{`regexp:^a#b\?c.*$`, "1.2.3.0/24", "full:x.example.com"}
	for _, v := range values {
		if err := store.AddEntry(name, v); err != nil {
			t.Fatalf("add %q: %v", v, err)
		}
	}

	s := &Server{Shunts: store, Reconciler: &countingReconciler{}, Logger: slog.New(slog.NewTextHandler(os.Stderr, nil)), mux: http.NewServeMux()}
	s.routes()

	for _, v := range values {
		path := "/shunts/" + url.PathEscape(name) + "/entries/" + url.PathEscape(v)
		req := httptest.NewRequest(http.MethodDelete, path, nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("DELETE %s: status %d body %s", path, rec.Code, rec.Body.String())
		}
		sh, err := store.Get(name)
		if err != nil {
			t.Fatal(err)
		}
		if sh.HasEntry(v) {
			t.Fatalf("entry %q still present after delete", v)
		}
	}
}
