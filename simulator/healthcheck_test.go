package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckHealth(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/healthz" {
					t.Errorf("unexpected healthcheck path: %s", r.URL.Path)
				}
				w.WriteHeader(status)
			}))
			defer server.Close()
			t.Setenv("SIMULATOR_LISTEN_ADDR", strings.TrimPrefix(server.URL, "http://"))
			if err := checkHealth(); (err == nil) != (status == http.StatusOK) {
				t.Errorf("checkHealth() error = %v, status = %d", err, status)
			}
		})
	}
}

func TestCheckHealthInvalidAddress(t *testing.T) {
	t.Setenv("SIMULATOR_LISTEN_ADDR", "invalid")
	if err := checkHealth(); err == nil {
		t.Fatal("expected an error for an invalid listen address")
	}
}
