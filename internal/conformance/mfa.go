// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// RunMFA pins the contract of ports.MFARepository.
func RunMFA(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0).UTC()
	setup := func(t *testing.T) (ports.Store, int64) {
		s := open(t)
		return s, mustCreate(t, s.Users(), newUser("mia", "mia@example.org"))
	}
	counts := func(t *testing.T, m ports.MFARepository, id int64) (totp, webauthn, recovery int) {
		t.Helper()
		var err error
		if totp, err = m.CountConfirmedTOTP(ctx, id); err != nil {
			t.Fatal(err)
		}
		if webauthn, err = m.CountWebAuthn(ctx, id); err != nil {
			t.Fatal(err)
		}
		if recovery, err = m.CountUnusedRecoveryCodes(ctx, id); err != nil {
			t.Fatal(err)
		}
		return
	}

	t.Run("MissingRows", func(t *testing.T) {
		s, id := setup(t)
		m := s.MFA()
		if a, b, c := counts(t, m, id); a != 0 || b != 0 || c != 0 {
			t.Fatalf("counts on a fresh account = %d, %d, %d", a, b, c)
		}
		if _, _, err := m.ConfirmedTOTP(ctx, id); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("ConfirmedTOTP: %v", err)
		}
		if _, _, err := m.TOTP(ctx, id); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("TOTP: %v", err)
		}
		if n, err := m.ConfirmTOTP(ctx, id, 5); err != nil || n != 0 {
			t.Fatalf("ConfirmTOTP = %d, %v", n, err)
		}
		if n, err := m.AdvanceTOTPCounter(ctx, id, 5); err != nil || n != 0 {
			t.Fatalf("AdvanceTOTPCounter = %d, %v", n, err)
		}
		if n, err := m.UseRecoveryCode(ctx, id, "h"); err != nil || n != 0 {
			t.Fatalf("UseRecoveryCode = %d, %v", n, err)
		}
		if l, err := m.WebAuthnKeys(ctx, id); err != nil || len(l) != 0 {
			t.Fatalf("WebAuthnKeys = %v, %v", l, err)
		}
		if l, err := m.ListWebAuthn(ctx, id); err != nil || len(l) != 0 {
			t.Fatalf("ListWebAuthn = %v, %v", l, err)
		}
		if n, err := m.RenameWebAuthn(ctx, 1, id, "x"); err != nil || n != 0 {
			t.Fatalf("RenameWebAuthn = %d, %v", n, err)
		}
		if _, err := m.WebAuthnOwner(ctx, 1); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("WebAuthnOwner: %v", err)
		}
		if _, _, err := m.UseResetRequest(ctx, "missing", now); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("UseResetRequest: %v", err)
		}
		for name, err := range map[string]error{
			"DeleteTOTP":                 m.DeleteTOTP(ctx, id),
			"DeleteRecoveryCodes":        m.DeleteRecoveryCodes(ctx, id),
			"DeleteWebAuthn":             m.DeleteWebAuthn(ctx, 1, id),
			"DeleteAllWebAuthn":          m.DeleteAllWebAuthn(ctx, id),
			"RecordWebAuthnUse":          m.RecordWebAuthnUse(ctx, 1, id, 5),
			"DeleteResetRequest":         m.DeleteResetRequest(ctx, "missing"),
			"DeleteResetRequestsForUser": m.DeleteResetRequestsForUser(ctx, id),
		} {
			if err != nil {
				t.Fatalf("%s on missing rows: %v", name, err)
			}
		}
	})

	t.Run("TOTP", func(t *testing.T) {
		s, id := setup(t)
		m := s.MFA()
		if err := m.StartTOTP(ctx, id, "s1"); err != nil {
			t.Fatal(err)
		}
		if sec, ok, err := m.TOTP(ctx, id); err != nil || sec != "s1" || ok {
			t.Fatalf("TOTP = %q, %v, %v", sec, ok, err)
		}
		if _, _, err := m.ConfirmedTOTP(ctx, id); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("an unconfirmed authenticator counts as confirmed")
		}
		if n, _ := m.CountConfirmedTOTP(ctx, id); n != 0 {
			t.Fatal("unconfirmed authenticator counted")
		}
		if err := m.StartTOTP(ctx, id, "s2"); err != nil {
			t.Fatal("StartTOTP must replace an existing authenticator:", err)
		}
		if n, err := m.ConfirmTOTP(ctx, id, 10); err != nil || n != 1 {
			t.Fatalf("ConfirmTOTP = %d, %v", n, err)
		}
		if n, _ := m.ConfirmTOTP(ctx, id, 11); n != 0 {
			t.Fatal("a confirmed authenticator was confirmed again")
		}
		if sec, last, err := m.ConfirmedTOTP(ctx, id); err != nil || sec != "s2" || last != 10 {
			t.Fatalf("ConfirmedTOTP = %q, %d, %v", sec, last, err)
		}
		if n, _ := m.CountConfirmedTOTP(ctx, id); n != 1 {
			t.Fatal("confirmed authenticator not counted")
		}
		if n, _ := m.AdvanceTOTPCounter(ctx, id, 10); n != 0 {
			t.Fatal("the same time step was accepted twice")
		}
		if n, err := m.AdvanceTOTPCounter(ctx, id, 12); err != nil || n != 1 {
			t.Fatalf("AdvanceTOTPCounter = %d, %v", n, err)
		}
		if n, _ := m.AdvanceTOTPCounter(ctx, id, 11); n != 0 {
			t.Fatal("an older time step was accepted")
		}
		if err := m.StartTOTP(ctx, id, "s3"); err != nil {
			t.Fatal(err)
		}
		if sec, ok, _ := m.TOTP(ctx, id); sec != "s3" || ok {
			t.Fatal("StartTOTP must reset the authenticator to unconfirmed")
		}
		if n, _ := m.ConfirmTOTP(ctx, id, 1); n != 1 {
			t.Fatal("the restarted authenticator must accept time step 1 (counter reset)")
		}
		if err := m.DeleteTOTP(ctx, id); err != nil {
			t.Fatal(err)
		}
		if _, _, err := m.TOTP(ctx, id); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("DeleteTOTP kept the authenticator")
		}
	})

	t.Run("RecoveryCodes", func(t *testing.T) {
		s, id := setup(t)
		other := mustCreate(t, s.Users(), newUser("ned", "ned@example.org"))
		m := s.MFA()
		for _, h := range []string{"a", "b", "c"} {
			if err := m.AddRecoveryCode(ctx, id, h); err != nil {
				t.Fatal(err)
			}
		}
		if err := m.AddRecoveryCode(ctx, id, "a"); err == nil {
			t.Fatal("a duplicate code was stored")
		}
		if err := m.AddRecoveryCode(ctx, other, "a"); err != nil {
			t.Fatal("another account may have the same code hash:", err)
		}
		if n, _ := m.CountUnusedRecoveryCodes(ctx, id); n != 3 {
			t.Fatalf("CountUnusedRecoveryCodes = %d", n)
		}
		if n, err := m.UseRecoveryCode(ctx, id, "a"); err != nil || n != 1 {
			t.Fatalf("UseRecoveryCode = %d, %v", n, err)
		}
		if n, _ := m.UseRecoveryCode(ctx, id, "a"); n != 0 {
			t.Fatal("a recovery code worked twice")
		}
		if n, _ := m.UseRecoveryCode(ctx, id, "zzz"); n != 0 {
			t.Fatal("an unknown code worked")
		}
		if n, _ := m.CountUnusedRecoveryCodes(ctx, id); n != 2 {
			t.Fatalf("CountUnusedRecoveryCodes after use = %d", n)
		}
		if n, _ := m.CountUnusedRecoveryCodes(ctx, other); n != 1 {
			t.Fatal("using a code touched another account")
		}
		if err := m.DeleteRecoveryCodes(ctx, id); err != nil {
			t.Fatal(err)
		}
		if n, _ := m.CountUnusedRecoveryCodes(ctx, id); n != 0 {
			t.Fatal("DeleteRecoveryCodes kept codes")
		}
		if err := m.AddRecoveryCode(ctx, id, "a"); err != nil {
			t.Fatal("DeleteRecoveryCodes must remove used codes too:", err)
		}
	})

	t.Run("RecoveryCodeConcurrentUse", func(t *testing.T) {
		s, id := setup(t)
		m := s.MFA()
		if err := m.AddRecoveryCode(ctx, id, "once"); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		results := make(chan int64, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				n, err := m.UseRecoveryCode(ctx, id, "once")
				if err != nil {
					t.Error(err)
				}
				results <- n
			}()
		}
		wg.Wait()
		close(results)
		var total int64
		for n := range results {
			total += n
		}
		if total != 1 {
			t.Fatalf("the code was used %d times", total)
		}
	})

	t.Run("WebAuthn", func(t *testing.T) {
		s, id := setup(t)
		other := mustCreate(t, s.Users(), newUser("ned", "ned@example.org"))
		m := s.MFA()
		if err := m.AddWebAuthn(ctx, id, []byte{1}, []byte{0xa}, -7, 3, "key one"); err != nil {
			t.Fatal(err)
		}
		if err := m.AddWebAuthn(ctx, id, []byte{2}, []byte{0xb}, -257, 0, "key two"); err != nil {
			t.Fatal(err)
		}
		if err := m.AddWebAuthn(ctx, other, []byte{1}, []byte{0xc}, -7, 0, "dup"); !errors.Is(err, ports.ErrDuplicate) {
			t.Fatalf("a stored credential id was stored again: %v", err)
		}
		keys, err := m.WebAuthnKeys(ctx, id)
		if err != nil || len(keys) != 2 {
			t.Fatalf("WebAuthnKeys = %v, %v", keys, err)
		}
		k := keys[0]
		if !bytes.Equal(k.CredID, []byte{1}) || !bytes.Equal(k.PublicKey, []byte{0xa}) || k.Alg != -7 || k.SignCount != 3 || keys[1].Alg != -257 || keys[0].RowID >= keys[1].RowID {
			t.Fatalf("WebAuthnKeys = %+v", keys)
		}
		list, err := m.ListWebAuthn(ctx, id)
		if err != nil || len(list) != 2 || list[0].RowID != k.RowID || list[0].Name != "key one" || list[0].LastUsedAt != nil || list[0].CreatedAt.IsZero() {
			t.Fatalf("ListWebAuthn = %+v, %v", list, err)
		}
		if n, _ := m.CountWebAuthn(ctx, id); n != 2 {
			t.Fatalf("CountWebAuthn = %d", n)
		}
		if owner, err := m.WebAuthnOwner(ctx, k.RowID); err != nil || owner != id {
			t.Fatalf("WebAuthnOwner = %d, %v", owner, err)
		}
		if err := m.RecordWebAuthnUse(ctx, k.RowID, id, 9); err != nil {
			t.Fatal(err)
		}
		if keys, _ := m.WebAuthnKeys(ctx, id); keys[0].SignCount != 9 {
			t.Fatalf("RecordWebAuthnUse did not store the counter: %+v", keys[0])
		}
		if list, _ := m.ListWebAuthn(ctx, id); list[0].LastUsedAt == nil {
			t.Fatal("RecordWebAuthnUse did not set the last use")
		}
		if err := m.RecordWebAuthnUse(ctx, k.RowID, other, 20); err != nil {
			t.Fatal(err)
		}
		if keys, _ := m.WebAuthnKeys(ctx, id); keys[0].SignCount != 9 {
			t.Fatal("RecordWebAuthnUse changed another account's credential")
		}
		if n, _ := m.RenameWebAuthn(ctx, k.RowID, other, "x"); n != 0 {
			t.Fatal("renamed another account's credential")
		}
		if n, err := m.RenameWebAuthn(ctx, k.RowID, id, "renamed"); err != nil || n != 1 {
			t.Fatalf("RenameWebAuthn = %d, %v", n, err)
		}
		if list, _ := m.ListWebAuthn(ctx, id); list[0].Name != "renamed" {
			t.Fatal("rename not stored")
		}
		if err := m.DeleteWebAuthn(ctx, k.RowID, other); err != nil {
			t.Fatal(err)
		}
		if n, _ := m.CountWebAuthn(ctx, id); n != 2 {
			t.Fatal("deleted another account's credential")
		}
		if err := m.DeleteWebAuthn(ctx, k.RowID, id); err != nil {
			t.Fatal(err)
		}
		if n, _ := m.CountWebAuthn(ctx, id); n != 1 {
			t.Fatal("DeleteWebAuthn kept the credential")
		}
		if err := m.DeleteAllWebAuthn(ctx, id); err != nil {
			t.Fatal(err)
		}
		if n, _ := m.CountWebAuthn(ctx, id); n != 0 {
			t.Fatal("DeleteAllWebAuthn kept credentials")
		}
	})

	t.Run("ResetRequests", func(t *testing.T) {
		s := open(t)
		verified := func(name string) int64 {
			nu := newUser(name, name+"@example.org")
			nu.EmailVerified = true
			id, err := s.Users().CreateRegistered(ctx, nu)
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
		id, admin := verified("ola"), verified("adm")
		unverified, err := s.Users().CreateRegistered(ctx, newUser("pip", "pip@example.org"))
		if err != nil {
			t.Fatal(err)
		}
		m := s.MFA()
		if err := m.CreateResetRequest(ctx, "r1", id, admin, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := m.UseResetRequest(ctx, "r1", now.Add(time.Hour)); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("UseResetRequest at expiry: %v", err)
		}
		uid, by, err := m.UseResetRequest(ctx, "r1", now)
		if err != nil || uid != id || by != admin {
			t.Fatalf("UseResetRequest = %d, %d, %v", uid, by, err)
		}
		if _, _, err := m.UseResetRequest(ctx, "r1", now); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("a reset request worked twice")
		}
		if err := m.CreateResetRequest(ctx, "r2", unverified, admin, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := m.UseResetRequest(ctx, "r2", now); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("a reset request for an unverified address worked")
		}
		if err := m.CreateResetRequest(ctx, "r3", id, admin, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := m.DeleteResetRequest(ctx, "r3"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := m.UseResetRequest(ctx, "r3", now); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("DeleteResetRequest kept the request")
		}
		if err := m.CreateResetRequest(ctx, "r4", id, admin, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := m.DeleteResetRequestsForUser(ctx, id); err != nil {
			t.Fatal(err)
		}
		if _, _, err := m.UseResetRequest(ctx, "r4", now); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("DeleteResetRequestsForUser kept a request")
		}
	})

	t.Run("ResetRequestConcurrentUse", func(t *testing.T) {
		s := open(t)
		nu := newUser("qin", "qin@example.org")
		nu.EmailVerified = true
		id, err := s.Users().CreateRegistered(ctx, nu)
		if err != nil {
			t.Fatal(err)
		}
		m := s.MFA()
		if err := m.CreateResetRequest(ctx, "once", id, 0, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wins := make(chan bool, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, err := m.UseResetRequest(ctx, "once", now)
				if err != nil && !errors.Is(err, ports.ErrNotFound) {
					t.Error(err)
				}
				wins <- err == nil
			}()
		}
		wg.Wait()
		close(wins)
		n := 0
		for w := range wins {
			if w {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("the reset request was used %d times", n)
		}
	})
}
