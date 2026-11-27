// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnlite

import (
	"crypto/rand"
	"net/url"
	"strconv"
	"strings"
)

// RP identifies the relying party: the WebAuthn RP ID (a host name, no port)
// and the exact origin browsers report in clientDataJSON.
type RP struct {
	ID     string
	Origin string
}

// RPFromAppURL derives the RP from the configured application URL. It reports
// false unless the URL is a secure context WebAuthn can run in: https with a
// DNS host name, or http on localhost, 127.0.0.1 or [::1]. Userinfo, paths other
// than "/", queries, fragments, trailing dots, non-ASCII hosts and invalid ports
// are rejected. Default ports are dropped from the origin, like browsers do.
//
// Note: browsers refuse IP literals as RP IDs, so http://127.0.0.1 is accepted
// here for development parity but only "localhost" works in real browsers.
func RPFromAppURL(appURL string) (RP, bool) {
	u, err := url.Parse(strings.TrimSpace(appURL))
	if err != nil || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return RP{}, false
	}
	if u.Path != "" && u.Path != "/" {
		return RP{}, false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return RP{}, false
	}
	host := u.Hostname()
	if host == "" || strings.HasSuffix(host, ".") {
		return RP{}, false
	}
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 || host[i] <= 0x20 {
			return RP{}, false
		}
	}
	host = strings.ToLower(host)
	isIP := strings.Contains(host, ":") || isIPv4(host)
	switch u.Scheme {
	case "http":
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return RP{}, false
		}
	case "https":
		if isIP {
			return RP{}, false // an RP ID must be a domain, not an IP literal
		}
	}
	port := u.Port()
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return RP{}, false
		}
		if (u.Scheme == "https" && p == 443) || (u.Scheme == "http" && p == 80) {
			port = ""
		} else {
			port = strconv.Itoa(p)
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return RP{}, false // "host:" with an empty port
	}
	originHost := host
	if strings.Contains(host, ":") {
		originHost = "[" + host + "]"
	}
	origin := u.Scheme + "://" + originHost
	if port != "" {
		origin += ":" + port
	}
	return RP{ID: host, Origin: origin}, true
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
	}
	return true
}

// NewChallenge returns 32 cryptographically random bytes.
func NewChallenge() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
