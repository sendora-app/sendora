// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"net/http"

	"github.com/sendora-app/sendora/internal/capabilities"
	"github.com/sendora-app/sendora/internal/flavour"
)

// flavour is the flavour this server runs in: a tenant served by the Cluster
// flavour (attachCluster), a tenant of the community multi-tenant host, or the
// single-tenant installation.
func (s *Server) flavour() flavour.Flavour {
	if s.cl != nil {
		return flavour.Cluster
	}
	if s.tenant != nil {
		return flavour.Multi
	}
	return flavour.Single
}

// capabilitiesHandler: GET /api/capabilities (public; the UI reads it at boot,
// before sign-in). Design 2A.4 #4. The version is already public through the
// footer's source link (AGPL section 13), so it adds nothing new here.
func (s *Server) capabilitiesHandler(w http.ResponseWriter, r *http.Request) {
	f := s.flavour()
	jout(w, 200, map[string]any{
		"flavour":  f,
		"version":  s.Version,
		"features": capabilities.Evaluate(f),
	})
}
