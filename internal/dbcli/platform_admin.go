// SPDX-License-Identifier: AGPL-3.0-or-later

package dbcli

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// platformAdminBcryptCost matches the application's password hashing cost.
var platformAdminBcryptCost = 12

// platformAdminReset is the offline recovery of a platform administrator in
// multi-tenant mode (stop the server first): it clears the administrator's
// authenticator (-mfa) and/or sets a temporary password (-password) that
// must be changed at the next sign-in, unlocks the account and ends the
// administrator's sessions. The action is recorded in the platform audit log.
func platformAdminReset(dataDir, keyFile, user string, mfa, password bool) error {
	if dataDir == "" {
		return errors.New("data-dir is required (the DATA_DIR of the stopped multi-tenant installation)")
	}
	if user == "" {
		return errors.New("user is required (the platform administrator's username)")
	}
	if !mfa && !password {
		return errors.New("choose what to reset: -mfa (remove the authenticator), -password (set a temporary password), or both")
	}
	if _, err := os.Stat(filepath.Join(dataDir, store.PlatformDBFile)); err != nil {
		return fmt.Errorf("no platform database in %s: %v", dataDir, err)
	}
	master, err := store.ReadDatabaseKey(keyFile)
	if err != nil {
		return err
	}
	defer clear(master)
	p, err := platform.Open(dataDir, master, false)
	if err != nil {
		return fmt.Errorf("platform database: %w", err)
	}
	defer p.Close()
	a, err := p.AdminByName(user)
	if err != nil {
		return fmt.Errorf("platform administrator %q not found", user)
	}
	var done []string
	if mfa {
		if err := p.ResetTOTP(a.ID); err != nil {
			return err
		}
		done = append(done, "authenticator removed")
	}
	var temp string
	if password {
		temp, err = temporaryPassword()
		if err != nil {
			return err
		}
		h, err := bcrypt.GenerateFromPassword([]byte(temp), platformAdminBcryptCost)
		if err != nil {
			return err
		}
		if err := p.SetTemporaryPassword(a.ID, string(h)); err != nil {
			return err
		}
		done = append(done, "temporary password set (must be changed at the next sign-in)")
	}
	detail := strings.Join(done, "; ") + "; sessions ended (offline, sendora-db)"
	if err := p.Audit(0, "sendora-db", "platform_admin_offline_reset", "admin "+a.Username, "ok", detail, ""); err != nil {
		return fmt.Errorf("the reset was applied but the platform audit record could not be written: %v", err)
	}
	fmt.Fprintf(stdout, "Platform administrator %s: %s.\n", a.Username, detail)
	if temp != "" {
		fmt.Fprintf(stdout, "Temporary password (shown once): %s\n", temp)
	}
	if mfa && p.MFARequired() {
		fmt.Fprintln(stdout, "An authenticator must be set up again at the next sign-in (platform_mfa_required is on).")
	}
	return nil
}

// temporaryPassword returns 20 random characters from an unambiguous alphabet.
func temporaryPassword() (string, error) {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}
