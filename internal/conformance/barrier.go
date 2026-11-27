// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/barrier"
	"github.com/sendora-app/sendora/internal/ports"
)

// outcomeStore injects a commit outcome into every write transaction of a
// real store (design 14.2: injected unknown outcomes).
type outcomeStore struct {
	ports.Store
	outcome ports.CommitOutcome
}

func (s outcomeStore) Begin(ctx context.Context) (ports.Tx, error) {
	tx, err := s.Store.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return outcomeTx{Tx: tx, outcome: s.outcome}, nil
}

type outcomeTx struct {
	ports.Tx
	outcome ports.CommitOutcome
}

func (t outcomeTx) Commit() error {
	switch t.outcome {
	case ports.Unknown:
		// The write may or may not survive; here it does (the worst case
		// for a worker that would act on it).
		if err := t.Tx.Commit(); err != nil {
			return err
		}
		return fmt.Errorf("%w: injected", ports.ErrOutcomeUnknown)
	case ports.Failed:
		t.Tx.Rollback()
		return errors.New("injected failure before COMMIT")
	}
	return t.Tx.Commit()
}

// RunClaimBarrier: a worker performs an external effect only after its claim
// committed cleanly (design 4.3); unknown and failed claim outcomes perform no
// effect, and a claimed download mail is not due for other workers until its
// lease ends.
func RunClaimBarrier(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	setup := func(t *testing.T) (ports.Store, int64, time.Time) {
		s := open(t)
		owner := mustCreate(t, s.Users(), newUser("ben", "ben@example.org"))
		share := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-b", Name: "B"})
		now := time.Now()
		id, err := s.DownloadMails().Reserve(ctx, share, "r@example.org", "en", `{}`, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.DownloadMails().Activate(ctx, id, now.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
		return s, id, now
	}
	claim := func(id int64, now time.Time) func(ports.Tx) (bool, error) {
		return func(tx ports.Tx) (bool, error) {
			n, err := tx.DownloadMails().Claim(ctx, id, now, now.Add(2*time.Minute))
			return n == 1, err
		}
	}

	t.Run("CleanCommitActs", func(t *testing.T) {
		s, id, now := setup(t)
		sent := 0
		acted, err := barrier.Run(ctx, s, "test", claim(id, now), func() error { sent++; return nil })
		if !acted || err != nil || sent != 1 {
			t.Fatalf("acted=%v err=%v sent=%d", acted, err, sent)
		}
		if _, err := s.DownloadMails().NextDue(ctx, now.Add(time.Minute)); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("a claimed job is due before its lease ends")
		}
		if job, err := s.DownloadMails().NextDue(ctx, now.Add(3*time.Minute)); err != nil || job.ID != id {
			t.Fatalf("job after the lease: %+v, %v", job, err)
		}
		// A second worker that read the job before the claim cannot claim it.
		if acted, _ := barrier.Run(ctx, s, "test", claim(id, now), func() error { sent++; return nil }); acted || sent != 1 {
			t.Fatal("a job was claimed twice")
		}
	})
	for _, o := range []ports.CommitOutcome{ports.Unknown, ports.Failed} {
		t.Run("NoEffectOn"+o.String(), func(t *testing.T) {
			s, id, now := setup(t)
			sent := 0
			before := barrier.UnknownTotal()
			acted, err := barrier.Run(ctx, outcomeStore{Store: s, outcome: o}, "test", claim(id, now), func() error { sent++; return nil })
			if acted || sent != 0 || ports.OutcomeOf(err) != o {
				t.Fatalf("outcome %v: acted=%v sent=%d err=%v", o, acted, sent, err)
			}
			if o == ports.Unknown && barrier.UnknownTotal() != before+1 {
				t.Fatal("an unknown outcome was not reported")
			}
			// Retried later: the job comes back (after the lease when the
			// unknown claim did survive) and a clean claim acts once.
			later := now.Add(3 * time.Minute)
			if acted, err := barrier.Run(ctx, s, "test", claim(id, later), func() error { sent++; return nil }); !acted || err != nil || sent != 1 {
				t.Fatalf("retry: acted=%v err=%v sent=%d", acted, err, sent)
			}
		})
	}
	t.Run("NothingToClaim", func(t *testing.T) {
		s, _, now := setup(t)
		acted, err := barrier.Run(ctx, s, "test", claim(9999, now), func() error { t.Fatal("acted"); return nil })
		if acted || err != nil {
			t.Fatalf("acted=%v err=%v", acted, err)
		}
	})
}
