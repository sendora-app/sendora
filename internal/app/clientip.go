// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ParseTrustedProxies parses a comma/space separated list of IPs and CIDRs
// (SENDORA_TRUSTED_PROXIES). An empty list trusts nothing.
func ParseTrustedProxies(list string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, item := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if !strings.Contains(item, "/") {
			ip := net.ParseIP(item)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted proxy %q", item)
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy %q", item)
		}
		out = append(out, n)
	}
	return out, nil
}

// SetTrustedProxies installs the reverse proxies whose X-Forwarded-* headers are
// believed. Called once at startup, before serving.
func (s *Server) SetTrustedProxies(nets []*net.IPNet) { s.trustedProxies = nets }

func (s *Server) trusted(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range s.trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func peerHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// peerTrusted reports whether the TCP peer is a configured trusted proxy.
func (s *Server) peerTrusted(r *http.Request) bool {
	return s.trusted(net.ParseIP(peerHost(r)))
}

// clientIP is the address used for rate limiting and download records. Forwarded
// headers are honoured only when the TCP peer is a trusted proxy, and then the
// right-most address that is not itself a trusted proxy wins (anything to its
// left is client-controlled). An unparsable entry falls back to the peer.
func (s *Server) clientIP(r *http.Request) string {
	s.noteForwardedHeader(r)
	peer := peerHost(r)
	if !s.trusted(net.ParseIP(peer)) {
		return peer
	}
	parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		token := strings.TrimSpace(parts[i])
		if token == "" {
			continue
		}
		ip := net.ParseIP(token)
		if ip == nil {
			return peer
		}
		if s.trusted(ip) {
			continue
		}
		return ip.String()
	}
	return peer
}

// requestHTTPS reports whether the client reached us over HTTPS: directly via TLS,
// or through a trusted proxy that says so.
func (s *Server) requestHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return s.peerTrusted(r) && strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]), "https")
}
