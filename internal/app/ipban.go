// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// Address bans ("fail2ban for Sendora"): repeated failed sign-in style requests
// (wrong password, wrong MFA code, wrong share password) from one client address
// block that address from the sign-in style routes for a while. Repeat offenders
// are blocked for twice as long each time, up to a day. Downloads of public
// shares, token refresh and existing sessions are not affected. Bans are kept in
// the database so a restart does not clear them; administrators can lift them.
const (
	ipBanThreshold = 10
	ipBanWindow    = 10 * time.Minute
	ipBanBase      = 30 * time.Minute
	ipBanMax       = 24 * time.Hour
	ipBanMemory    = 24 * time.Hour // strikes are forgotten after this long without a new ban
	ipBanMaxKeys   = 4096
	ipBanMaxList   = 50

	settingIPBanEnabled   = "ip_ban_enabled"
	settingIPBanAllowlist = "ip_ban_allowlist"
)

type ipBan struct {
	until      time.Time
	strikes    int
	lastStrike time.Time
}
type ipFail struct {
	count   int
	expires time.Time
}
type ipBanState struct {
	mu    sync.Mutex
	bans  map[string]ipBan
	fails map[string]ipFail
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	// failed is set by a handler that rejected a credential check (see
	// markAuthFailure); routes that also carry ordinary signed-in traffic count
	// only these, not every 401/403.
	failed bool
}

func (r *statusRecorder) WriteHeader(code int)        { r.status = code; r.ResponseWriter.WriteHeader(code) }
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// ipBanKey groups IPv6 clients by /64 (one household or host can use any address
// in its prefix); IPv4 and unparsable values are used as is.
func ipBanKey(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ip
	}
	if v4 := p.To4(); v4 != nil {
		return v4.String()
	}
	return p.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// ipBansEnabled is off when the recovery switch is set or the setting is false.
func (s *Server) ipBansEnabled() bool {
	if os.Getenv("SENDORA_DISABLE_IP_BANS") == "true" {
		return false
	}
	v := s.St.Setting(settingIPBanEnabled)
	return v == "" || v == "true"
}

func parseIPList(v string) (nets []*net.IPNet, canonical []string, err error) {
	for _, item := range strings.FieldsFunc(v, func(r rune) bool { return r == '\n' || r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r' }) {
		var n *net.IPNet
		if strings.Contains(item, "/") {
			_, parsed, e := net.ParseCIDR(item)
			if e != nil {
				return nil, nil, fmt.Errorf("invalid address or range: %s", clipForMessage(item))
			}
			n = parsed
		} else {
			ip := net.ParseIP(item)
			if ip == nil {
				return nil, nil, fmt.Errorf("invalid address or range: %s", clipForMessage(item))
			}
			bits := 128
			if v4 := ip.To4(); v4 != nil {
				ip, bits = v4, 32
			}
			n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		nets = append(nets, n)
		canonical = append(canonical, n.String())
	}
	if len(nets) > ipBanMaxList {
		return nil, nil, fmt.Errorf("at most %d addresses or ranges", ipBanMaxList)
	}
	return nets, canonical, nil
}

// validateIPBanSetting validates and normalises the two settings; the allowlist
// is rewritten to one canonical entry per line.
func validateIPBanSetting(key string, val *string) (owned bool, err error) {
	switch key {
	case settingIPBanEnabled:
		if *val != "true" && *val != "false" {
			return true, fmt.Errorf("%s must be true or false", key)
		}
		return true, nil
	case settingIPBanAllowlist:
		if len(*val) > 4096 {
			return true, fmt.Errorf("allowlist too long")
		}
		_, canonical, e := parseIPList(*val)
		if e != nil {
			return true, e
		}
		*val = strings.Join(canonical, "\n")
		return true, nil
	}
	return false, nil
}

func (s *Server) ipAllowlisted(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	nets, _, err := parseIPList(s.St.Setting(settingIPBanAllowlist))
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

func (s *Server) loadIPBans() {
	s.ipBans.mu.Lock()
	defer s.ipBans.mu.Unlock()
	s.ipBans.bans = map[string]ipBan{}
	stored, err := s.St.Repos().IPBans().List(context.Background())
	if err != nil {
		return
	}
	for _, b := range stored {
		s.ipBans.bans[b.Key] = ipBan{until: b.Until, strikes: b.Strikes, lastStrike: b.LastStrike}
	}
}

// ipBlocked reports whether the client address is currently banned.
func (s *Server) ipBlocked(ip string) (time.Duration, bool) {
	if !s.ipBansEnabled() {
		return 0, false
	}
	key := ipBanKey(ip)
	s.ipBans.mu.Lock()
	b, ok := s.ipBans.bans[key]
	s.ipBans.mu.Unlock()
	if !ok || !time.Now().Before(b.until) {
		return 0, false
	}
	if s.ipAllowlisted(ip) {
		return 0, false
	}
	return time.Until(b.until), true
}

// noteIPFailure counts a failed attempt and bans the address at the threshold.
func (s *Server) noteIPFailure(ip string) {
	if !s.ipBansEnabled() || s.ipAllowlisted(ip) {
		return
	}
	key := ipBanKey(ip)
	now := time.Now()
	if reached, handled := s.sharedIPFailure(key); handled {
		if !reached {
			return
		}
		// Strikes count from the bans of every replica.
		s.loadIPBans()
		s.ipBans.mu.Lock()
		s.banLocked(key, now)
		return
	}
	s.ipBans.mu.Lock()
	if s.ipBans.fails == nil {
		s.ipBans.fails = map[string]ipFail{}
	}
	f := s.ipBans.fails[key]
	if !now.Before(f.expires) {
		if len(s.ipBans.fails) >= ipBanMaxKeys {
			s.evictIPFails(now)
		}
		f = ipFail{expires: now.Add(ipBanWindow)}
	}
	f.count++
	if f.count < ipBanThreshold {
		s.ipBans.fails[key] = f
		s.ipBans.mu.Unlock()
		return
	}
	delete(s.ipBans.fails, key)
	s.banLocked(key, now)
}

// banLocked bans key (strikes grow while earlier bans are remembered),
// persists the ban and tells the other replicas. The caller holds
// ipBans.mu; banLocked releases it.
func (s *Server) banLocked(key string, now time.Time) {
	prev := s.ipBans.bans[key]
	strikes := 1
	if !prev.lastStrike.IsZero() && now.Sub(prev.lastStrike) < ipBanMemory {
		strikes = prev.strikes + 1
	}
	dur := ipBanBase
	for i := 1; i < strikes && dur < ipBanMax; i++ {
		dur *= 2
	}
	if dur > ipBanMax {
		dur = ipBanMax
	}
	b := ipBan{until: now.Add(dur), strikes: strikes, lastStrike: now}
	s.ipBans.bans[key] = b
	s.ipBans.mu.Unlock()
	s.St.Repos().IPBans().Put(context.Background(), ports.IPBan{Key: key, Until: b.until, Strikes: strikes, LastStrike: now})
	s.bansChanged()
	// The activity log never stores addresses, so only the fact is recorded.
	s.logEvent(0, "", "ip_banned", "", fmt.Sprintf("strike=%d minutes=%d", strikes, int(dur.Minutes())))
}

// evictIPFails makes room in the failure counters without wiping them: expired
// counters go first, then the quarter with the fewest failures, so flooding from
// many addresses cannot reset the counter of an address close to the threshold.
// The caller holds ipBans.mu.
func (s *Server) evictIPFails(now time.Time) {
	for k, v := range s.ipBans.fails {
		if !now.Before(v.expires) {
			delete(s.ipBans.fails, k)
		}
	}
	if len(s.ipBans.fails) < ipBanMaxKeys {
		return
	}
	type entry struct {
		key   string
		count int
	}
	all := make([]entry, 0, len(s.ipBans.fails))
	for k, v := range s.ipBans.fails {
		all = append(all, entry{k, v.count})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].count < all[j].count })
	for _, e := range all[:len(all)/4+1] {
		delete(s.ipBans.fails, e.key)
	}
}

// pruneIPBans forgets bans that have ended and whose strikes have expired, in
// memory and in the database (run by the maintenance job).
func (s *Server) pruneIPBans() {
	now := time.Now()
	s.ipBans.mu.Lock()
	for k, b := range s.ipBans.bans {
		if !now.Before(b.until) && now.Sub(b.lastStrike) >= ipBanMemory {
			delete(s.ipBans.bans, k)
		}
	}
	s.ipBans.mu.Unlock()
	s.St.Repos().IPBans().Prune(context.Background(), now, now.Add(-ipBanMemory))
}

type ipBanInfo struct {
	IP      string    `json:"ip"`
	Until   time.Time `json:"until"`
	Strikes int       `json:"strikes"`
}

func (s *Server) activeIPBans() []ipBanInfo {
	now := time.Now()
	s.ipBans.mu.Lock()
	defer s.ipBans.mu.Unlock()
	out := []ipBanInfo{}
	for k, b := range s.ipBans.bans {
		if now.Before(b.until) {
			out = append(out, ipBanInfo{IP: k, Until: b.until, Strikes: b.strikes})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Until.After(out[j].Until) })
	return out
}

// listIPBansHandler: GET /api/ip-bans (admin).
func (s *Server) listIPBansHandler(w http.ResponseWriter, r *http.Request) {
	jout(w, 200, map[string]any{
		"enabled":        s.ipBansEnabled(),
		"env_disabled":   os.Getenv("SENDORA_DISABLE_IP_BANS") == "true",
		"threshold":      ipBanThreshold,
		"window_minutes": int(ipBanWindow.Minutes()),
		"ban_minutes":    int(ipBanBase.Minutes()),
		"max_hours":      int(ipBanMax.Hours()),
		"your_ip":        s.clientIP(r),
		"bans":           s.activeIPBans(),
	})
}

// deleteIPBanHandler: DELETE /api/ip-bans?ip=... (admin). Also forgets strikes.
func (s *Server) deleteIPBanHandler(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("ip")
	s.ipBans.mu.Lock()
	_, found := s.ipBans.bans[key]
	delete(s.ipBans.bans, key)
	delete(s.ipBans.fails, key)
	s.ipBans.mu.Unlock()
	if !found {
		jerr(w, 404, "address not banned")
		return
	}
	s.St.Repos().IPBans().Delete(context.Background(), key)
	s.bansChanged()
	if me := s.ctxUser(r); me != nil {
		s.logEvent(me.ID, me.Username, "ip_unbanned", "", "")
	}
	jout(w, 200, map[string]any{"ok": true})
}
