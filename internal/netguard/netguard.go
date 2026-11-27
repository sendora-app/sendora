// SPDX-License-Identifier: AGPL-3.0-or-later

// Package netguard keeps server-side requests to targets a tenant
// administrator typed (SMTP server, OIDC issuer, audit webhook and syslog
// targets, object storage endpoints) away from the platform's own network in
// multi-tenant mode: loopback, private (RFC 1918, IPv6 ULA), link-local
// (including cloud instance metadata), carrier-grade NAT, unspecified,
// multicast, broadcast and other special-purpose addresses.
//
// It checks twice: CheckHost when a target is saved (a clear error for the
// administrator), and Control on every connection, after DNS resolution, on
// the address about to be connected. The second check is the one that
// matters: it also catches DNS rebinding (a name that resolved to a public
// address at save time and to 127.0.0.1 later) and redirects.
//
// Single-tenant installations do not use this package for these targets: the
// administrator of a single-tenant installation runs the server and may point
// it at internal services.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// ErrBlocked is returned (wrapped) for a target in a blocked range.
var ErrBlocked = errors.New("target not allowed: it resolves to a loopback, private, link-local, carrier-grade NAT or metadata address")

var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",       // "this network"
		"10.0.0.0/8",      // RFC 1918
		"100.64.0.0/10",   // carrier-grade NAT (RFC 6598), also Alibaba Cloud metadata 100.100.100.200
		"127.0.0.0/8",     // loopback
		"169.254.0.0/16",  // link-local, cloud metadata 169.254.169.254
		"172.16.0.0/12",   // RFC 1918
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // documentation
		"192.88.99.0/24",  // 6to4 relay anycast
		"192.168.0.0/16",  // RFC 1918
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // documentation
		"203.0.113.0/24",  // documentation
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved, broadcast
		"::/128",          // unspecified
		"::1/128",         // loopback
		"64:ff9b:1::/48",  // local-use NAT64
		"100::/64",        // discard
		"2001:db8::/32",   // documentation
		"fc00::/7",        // unique local (ULA), AWS IPv6 metadata fd00:ec2::254
		"fe80::/10",       // link-local
		"fec0::/10",       // site-local (deprecated)
		"ff00::/8",        // multicast
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// Blocked reports whether a connection to a may not be made. IPv4-mapped and
// NAT64 (64:ff9b::/96) and 6to4 (2002::/16) addresses are judged by the IPv4
// address they carry.
func Blocked(a netip.Addr) bool {
	if !a.IsValid() {
		return true
	}
	a = a.Unmap()
	if a.Is6() {
		b := a.As16()
		switch {
		case netip.MustParsePrefix("64:ff9b::/96").Contains(a):
			return Blocked(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
		case netip.MustParsePrefix("2002::/16").Contains(a):
			return Blocked(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}))
		}
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Control is a net.Dialer Control function: it runs after name resolution, on
// the address about to be connected, and refuses blocked addresses.
func Control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrBlocked, host)
	}
	if Blocked(ip) {
		return fmt.Errorf("%w (%s)", ErrBlocked, ip)
	}
	return nil
}

// Dialer returns a dialer that refuses blocked addresses at connect time.
func Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second, Control: Control}
}

// DialContext is Dialer(30s).DialContext, for HTTP transports.
func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return Dialer(30*time.Second).DialContext(ctx, network, address)
}

// LookupNetIP resolves host names for CheckHost (tests replace it).
var LookupNetIP = net.DefaultResolver.LookupNetIP

// CheckHost is the save-time check of a target host (a name or an IP literal,
// without port): it refuses the host when it is an internal name or when any
// of its addresses is blocked. A name that does not resolve is refused too: it
// cannot be checked, and a target that does not resolve is useless anyway.
func CheckHost(ctx context.Context, host string) error {
	host = strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), ".")
	if host == "" {
		return nil
	}
	if i := strings.IndexByte(host, '%'); i >= 0 { // zone: link-local only
		return fmt.Errorf("%w (%s)", ErrBlocked, host)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if Blocked(ip) {
			return fmt.Errorf("%w (%s)", ErrBlocked, ip)
		}
		return nil
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || !strings.Contains(lower, ".") {
		return fmt.Errorf("%w (%s)", ErrBlocked, host)
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".svc", ".cluster.local", ".lan", ".home.arpa"} {
		if strings.HasSuffix(lower, suffix) {
			return fmt.Errorf("%w (%s)", ErrBlocked, host)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("target %s could not be resolved", host)
	}
	for _, a := range addrs {
		if Blocked(a) {
			return fmt.Errorf("%w (%s -> %s)", ErrBlocked, host, a.Unmap())
		}
	}
	return nil
}

// HostOf returns the host part of "host", "host:port" or a URL.
func HostOf(target string) string {
	t := strings.TrimSpace(target)
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
		if j := strings.IndexAny(t, "/?#"); j >= 0 {
			t = t[:j]
		}
		if j := strings.LastIndexByte(t, '@'); j >= 0 {
			t = t[j+1:]
		}
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		return h
	}
	return strings.Trim(t, "[]")
}
