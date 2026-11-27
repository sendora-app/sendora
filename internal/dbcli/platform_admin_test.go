// SPDX-License-Identifier: AGPL-3.0-or-later

package dbcli

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sendora-app/sendora/internal/platform"
	"golang.org/x/crypto/bcrypt"
)

func TestPlatformAdminResetCommand(t *testing.T) {
	platformAdminBcryptCost = bcrypt.MinCost
	dir := t.TempDir()
	master := bytes.Repeat([]byte{0x24}, 32)
	keyFile := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(keyFile, master, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := platform.Open(dir, master, true)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := p.CreateFirstAdmin("root", "", "old-hash")
	p.SetPendingTOTP(a.ID, "SECRET")
	p.EnableTOTP(a.ID, 1)
	p.CreateSession("h", a.ID, "full", 3600e9)
	p.NoteLoginFailure(a.ID, 1, 3600e9)
	p.Close()

	for _, args := range [][]string{
		{"platform-admin-reset", "-data-dir", dir, "-key-file", keyFile, "-user", "root"},           // nothing chosen
		{"platform-admin-reset", "-data-dir", dir, "-key-file", keyFile, "-mfa"},                    // no user
		{"platform-admin-reset", "-data-dir", dir, "-key-file", keyFile, "-user", "nobody", "-mfa"}, // unknown
		{"platform-admin-reset", "-data-dir", t.TempDir(), "-key-file", keyFile, "-user", "root", "-mfa"},
	} {
		if err := run(args); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
	var out bytes.Buffer
	old := stdout
	stdout = &out
	err = run([]string{"platform-admin-reset", "-data-dir", dir, "-key-file", keyFile, "-user", "ROOT", "-mfa", "-password"})
	stdout = old
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`Temporary password \(shown once\): (\S+)`).FindStringSubmatch(out.String())
	if m == nil || len(m[1]) != 20 {
		t.Fatalf("output: %s", out.String())
	}
	p, err = platform.Open(dir, master, false)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	a, _ = p.AdminByName("root")
	if a.TOTPEnabled || a.TOTPSecret != "" || !a.MustChangePassword || a.LockedUntil != 0 || a.Failures != 0 {
		t.Fatalf("admin after reset: %+v", a)
	}
	if bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(m[1])) != nil {
		t.Fatal("temporary password does not match")
	}
	if _, err := p.SessionFor("h", 3600e9); err == nil {
		t.Fatal("session survived the reset")
	}
	recs, _ := p.AuditPage(0, 10)
	found := false
	for _, r := range recs {
		if r.Action == "platform_admin_offline_reset" && r.ActorName == "sendora-db" && strings.Contains(r.Detail, "temporary password") && strings.Contains(r.Detail, "authenticator removed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no platform audit record: %+v", recs)
	}
	if st, err := p.St.AuditVerifyIncremental(t.Context()); err != nil || !st.OK {
		t.Fatalf("platform audit chain: %+v %v", st, err)
	}
}
