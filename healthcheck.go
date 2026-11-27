// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// healthcheck implements "sendora healthcheck" for the container HEALTHCHECK:
// it asks the running server on this machine for /api/health and returns the
// process exit code (0 healthy, 1 not). The runtime image then needs no wget
// or curl.
func healthcheck() int {
	url := "http://" + net.JoinHostPort("127.0.0.1", env("PORT", "8080")) + "/api/health"
	if err := probeHealth(url, 2*time.Second); err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy:", err)
		return 1
	}
	return 0
}

func probeHealth(url string, timeout time.Duration) error {
	client := &http.Client{
		Timeout: timeout,
		// Never through a proxy, never somewhere else.
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", url, resp.Status)
	}
	return nil
}
