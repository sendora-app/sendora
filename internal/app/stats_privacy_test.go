// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"strings"
	"testing"
)

// Administrators must not learn which shares exist or how to open them: the
// statistics may only contain counts, never share names or share link IDs.
func TestAdminStatsDoNotRevealShares(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	alice := e.mkUser(admin, "alice", false)
	share := e.share(alice, map[string]string{"a.txt": "abc"}, map[string]any{"name": "AliceSecretShareName"})
	e.want(share, 201, "share")
	lid := share.S("long_id")
	e.want(e.do("GET", "/api/shares/"+lid+"/download", "", nil), 200, "download")
	r := e.do("GET", "/api/stats", admin, nil)
	e.want(r, 200, "stats")
	body := string(r.Body)
	for _, forbidden := range []string{lid, "AliceSecretShareName", "top_shares", "long_id"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("admin statistics contain %q: %s", forbidden, body)
		}
	}
	if r.J()["shares"].(float64) < 1 || r.J()["downloads"].(float64) < 1 {
		t.Fatalf("counts missing: %s", body)
	}
}
