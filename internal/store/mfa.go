// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"fmt"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
)

// migrateMFA: see sqlite.MigrateMFA.
func (s *Store) migrateMFA() error { return sqlite.MigrateMFA(s.DB) }

// ResetUserMFA removes every MFA factor and all sessions of one local user in
// an offline database (the application must be stopped). It is the recovery path
// for an administrator who is locked out by a lost authenticator.
func ResetUserMFA(path string, key []byte, username string) error {
	db, err := openCipherDB(path, key, false)
	if err != nil {
		return err
	}
	defer db.Close()
	a := sqlite.New(db)
	if len(key) == 32 {
		// The username is found through its blind index: the keys are needed.
		codec, err := columnCodecFor(db, key)
		if err != nil {
			return fmt.Errorf("the database's keys do not verify: %w", err)
		}
		if codec != nil {
			defer codec.Close()
			a.SetCodec(codec)
		}
	}
	tx, err := a.Begin(context.Background())
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ctx := context.Background()
	id, err := tx.Users().LocalIDByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	for _, step := range []func(context.Context, int64) error{
		tx.MFA().DeleteTOTP,
		tx.MFA().DeleteRecoveryCodes,
		tx.MFA().DeleteAllWebAuthn,
		func(ctx context.Context, id int64) error {
			_, err := tx.Sessions().RevokeAllForUser(ctx, id)
			return err
		},
		tx.Users().BumpMFAEpochAndClearLock,
	} {
		if err := step(ctx, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
