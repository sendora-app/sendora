// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"net"
	"net/http"
	"os"
)

// Administrator network restriction: admin_ip_allowlist (addresses and CIDR
// ranges, one per line; empty = no restriction) limits the administration and
// audit routes to these client addresses. The client address is the one used
// everywhere else (clientIP: forwarded headers only from trusted proxies).
// Refused requests get 403 and an access_denied audit record.
//
// Recovery: SENDORA_DISABLE_ADMIN_IP_ALLOWLIST=true switches the restriction
// off (for example after a change of the office address). Saving a list that
// does not contain the administrator's own current address is refused, unless
// that switch is set.

const (
	settingAdminIPAllowlist  = "admin_ip_allowlist"
	envDisableAdminAllowlist = "SENDORA_DISABLE_ADMIN_IP_ALLOWLIST"
	msgAdminNetworkDenied    = "administration is not allowed from this network address"
)

func adminAllowlistDisabled() bool { return os.Getenv(envDisableAdminAllowlist) == "true" }

// listContains reports whether ip is inside one of the entries of list. An
// unparsable stored list contains nothing (fail closed).
func listContains(list, ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	nets, _, err := parseIPList(list)
	if err != nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

// adminNetworkAllowed applies the restriction to a request.
func (s *Server) adminNetworkAllowed(r *http.Request) bool {
	if adminAllowlistDisabled() {
		return true
	}
	list := s.St.Setting(settingAdminIPAllowlist)
	if list == "" {
		return true
	}
	return listContains(list, s.clientIP(r))
}

// adminNetwork is the middleware on the administration and audit route groups.
func (s *Server) adminNetwork(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.adminNetworkAllowed(r) {
			s.auditAccessDenied(r, catSecurity, r.Method+" "+r.URL.Path, "admin_ip_allowlist")
			jerr(w, http.StatusForbidden, msgAdminNetworkDenied)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// adminAllowlistExcludesCaller returns a message when saving list would lock
// the calling administrator out ("" when it is fine).
func (s *Server) adminAllowlistExcludesCaller(r *http.Request, list string) string {
	if list == "" || adminAllowlistDisabled() {
		return ""
	}
	ip := s.clientIP(r)
	if listContains(list, ip) {
		return ""
	}
	return fmt.Sprintf("the list does not include your own address %s; add it, or set %s=true to override", ip, envDisableAdminAllowlist)
}
