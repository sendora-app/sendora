// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/sendora-app/sendora/internal/netguard"
	"golang.org/x/oauth2"
)

// Provider discovery, JWKS and token exchange are server-side requests to an
// address an administrator typed. They run through a dedicated client that
// refuses loopback, link-local (including cloud metadata) and unspecified
// targets after DNS resolution, so a hostile or hijacked name cannot point the
// server at itself or at an instance-metadata service. RFC 1918 and other
// private ranges stay reachable: self-hosted identity providers often live there.
const (
	oidcHTTPTimeout  = 5 * time.Second
	oidcFlowTimeout  = 10 * time.Second
	oidcMaxRedirects = 3
)

var errBlockedTarget = errors.New("address not allowed for provider requests")

// blockedProviderAddr reports whether an outgoing provider request may not
// connect to this address.
func blockedProviderAddr(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast() {
		return true
	}
	// Metadata endpoints outside the link-local ranges.
	for _, p := range metadataPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

var metadataPrefixes = []netip.Prefix{
	netip.MustParsePrefix("fd00:ec2::/32"),      // AWS IPv6 instance metadata
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud metadata
}

// providerDialControl runs after name resolution, on the address about to be
// connected, so DNS answers cannot slip past a name-based check.
func providerDialControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %s", errBlockedTarget, host)
	}
	if blockedProviderAddr(ip) {
		return fmt.Errorf("%w: %s", errBlockedTarget, ip)
	}
	return nil
}

func newProviderHTTPClient() *http.Client { return newProviderHTTPClientControl(providerDialControl) }

// newProviderHTTPClientControl builds the provider client with a dial check.
func newProviderHTTPClientControl(control func(network, address string, c syscall.RawConn) error) *http.Client {
	dialer := &net.Dialer{Timeout: oidcHTTPTimeout, Control: control}
	// No proxy: the guard must see the real destination, not a proxy's address.
	tr := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   oidcHTTPTimeout,
		ResponseHeaderTimeout: oidcHTTPTimeout,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   oidcHTTPTimeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) > oidcMaxRedirects {
				return fmt.Errorf("stopped after %d redirects", oidcMaxRedirects)
			}
			return nil
		},
	}
}

var providerClient = sync.OnceValue(newProviderHTTPClient)

// providerClientStrict is the client for providers a tenant's administrator
// configured in multi-tenant mode: private networks are refused as well
// (internal/netguard).
var providerClientStrict = sync.OnceValue(func() *http.Client { return newProviderHTTPClientControl(netguard.Control) })

// providerContextFor is providerContext with the client the provider needs:
// the strict one for a provider a guarded tenant's administrator configured,
// the standard one otherwise (single-tenant mode, providers from the server
// configuration).
func (s *Server) providerContextFor(parent context.Context, p *Provider) (context.Context, context.CancelFunc) {
	if s.guardTargets() && !p.Managed && parent.Value(oauth2.HTTPClient) == nil {
		parent = context.WithValue(parent, oauth2.HTTPClient, providerClientStrict())
	}
	return providerContext(parent)
}

// providerContext bounds an OIDC flow and routes its discovery, key and token
// requests through the guarded client (go-oidc and oauth2 both read the client
// from the context). A client already present in the context is kept.
func providerContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(parent, oidcFlowTimeout)
	if ctx.Value(oauth2.HTTPClient) == nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, providerClient())
	}
	return ctx, cancel
}
