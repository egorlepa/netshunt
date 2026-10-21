package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeHTTPDetachesMutatingRequests(t *testing.T) {
	tests := []struct {
		method       string
		wantCanceled bool
	}{
		{http.MethodGet, true},
		{http.MethodPost, false},
		{http.MethodPut, false},
		{http.MethodDelete, false},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			var gotErr error
			s := &Server{mux: http.NewServeMux()}
			s.mux.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) {
				gotErr = r.Context().Err()
			})

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			req := httptest.NewRequestWithContext(ctx, tt.method, "/x", nil)
			s.ServeHTTP(httptest.NewRecorder(), req)

			if canceled := gotErr != nil; canceled != tt.wantCanceled {
				t.Errorf("handler context canceled = %v, want %v", canceled, tt.wantCanceled)
			}
		})
	}
}
