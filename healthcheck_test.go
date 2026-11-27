// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestProbeHealth(t *testing.T) {
	status := http.StatusOK
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/health" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
	}))
	defer ts.Close()

	if err := probeHealth(ts.URL+"/api/health", 2*time.Second); err != nil {
		t.Fatalf("healthy server reported unhealthy: %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := probeHealth(ts.URL+"/api/health", 2*time.Second); err == nil {
		t.Fatal("503 reported as healthy")
	}

	u, _ := url.Parse(ts.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	t.Setenv("PORT", port)
	status = http.StatusOK
	if code := healthcheck(); code != 0 {
		t.Fatalf("healthcheck exit code %d for a healthy server", code)
	}
	status = http.StatusInternalServerError
	if code := healthcheck(); code != 1 {
		t.Fatalf("healthcheck exit code %d for an unhealthy server", code)
	}
}

func TestProbeHealthTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer ts.Close()
	if err := probeHealth(ts.URL+"/api/health", 100*time.Millisecond); err == nil {
		t.Fatal("a server that does not answer in time reported as healthy")
	}
}

func TestProbeHealthNoServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if err := probeHealth("http://"+addr+"/api/health", time.Second); err == nil {
		t.Fatal("no server reported as healthy")
	}
}
