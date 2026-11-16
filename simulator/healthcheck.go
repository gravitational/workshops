package main

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// checkHealth replaces curl in the distroless container's healthcheck.
func checkHealth() error {
	host, port, err := net.SplitHostPort(env("SIMULATOR_LISTEN_ADDR", ":8080"))
	if err != nil {
		return fmt.Errorf("healthcheck listen address: %w", err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return fmt.Errorf("healthcheck request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: unexpected status %s", resp.Status)
	}
	return nil
}
