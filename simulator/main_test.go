package main

import (
	"net/http/httptest"
	"testing"
)

func TestIsPolling(t *testing.T) {
	for _, tc := range []struct {
		method, target string
		want           bool
	}{
		{"GET", "/healthz", true},
		{"POST", "/_runner/jobs/claim", true},
		{"GET", "/example-org/teleport-k8s-demo/actions/runs/1.json", true},
		{"GET", "/example-org/teleport-k8s-demo/actions/runs/1", false},
		{"GET", "/_runner/jobs/claim", false},
		{"POST", "/_runner/runs/1/logs", false},
		{"POST", "/example-org/teleport-k8s-demo/actions/workflows/deploy.yaml/dispatches", false},
		{"GET", "/example-org/teleport-k8s-demo/blob/main/manifests/deployment.json", false},
	} {
		if got := isPolling(httptest.NewRequest(tc.method, tc.target, nil)); got != tc.want {
			t.Errorf("isPolling(%s %s) = %v, want %v", tc.method, tc.target, got, tc.want)
		}
	}
}
