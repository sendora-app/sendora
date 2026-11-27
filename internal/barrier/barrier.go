// SPDX-License-Identifier: AGPL-3.0-or-later

// Package barrier is the core rule for commit outcomes (docs/cluster/DESIGN.md
// 4.1 and 4.3), shared by request handling and workers in every flavour.
//
// A row that a worker merely reads may be an unreplicated commit from a
// cancelled synchronous-replication wait, and a failover can remove it. A
// worker therefore never performs an external effect (mail, webhook, audit
// forwarding, journal write) for a row it has only read: it first claims the
// row in a transaction of its own and commits. That commit record lies later
// in the WAL than the rows read, and a synchronous commit returns cleanly only
// after a standby has flushed WAL up to it, so a clean ports.Committed outcome
// proves the rows are replicated. Only then is the effect performed. A claim
// with outcome unknown or failed performs no effect and is retried later, so
// delivery is at-least-once and every external message carries a stable ID.
package barrier

import (
	"context"
	"encoding/json"
	"log"
	"sync/atomic"

	"github.com/sendora-app/sendora/internal/ports"
)

// Claim runs claim in a write transaction of st and commits it. It returns
// true only when claim reported a claimed row and the commit outcome is
// ports.Committed; only then may the caller act. A commit with outcome
// unknown is reported (ReportUnknown) and returned as an error.
func Claim(ctx context.Context, st ports.Store, op string, claim func(ports.Tx) (bool, error)) (bool, error) {
	tx, err := st.Begin(ctx)
	if err != nil {
		return false, err
	}
	ok, err := claim(tx)
	if err != nil || !ok {
		tx.Rollback()
		return false, err
	}
	if err := tx.Commit(); err != nil {
		if ports.OutcomeOf(err) == ports.Unknown {
			ReportUnknown(op, "", err)
		}
		return false, err
	}
	return true, nil
}

// Run claims (Claim) and performs act only after a clean claim commit. acted
// reports whether act ran; err is the claim's or act's error.
func Run(ctx context.Context, st ports.Store, op string, claim func(ports.Tx) (bool, error), act func() error) (acted bool, err error) {
	ok, err := Claim(ctx, st, op, claim)
	if !ok {
		return false, err
	}
	return true, act()
}

var unknownTotal atomic.Int64

// UnknownTotal is sendora_commit_outcome_unknown_total.
func UnknownTotal() int64 { return unknownTotal.Load() }

// ReportUnknown writes the reconciliation record of an unknown commit outcome
// to the process log (JSON, collected by the log pipeline) and counts it; it
// is never written to the database that may lose it (design 4.1 item 4).
// ref identifies the request (for example the idempotency-key hash).
func ReportUnknown(op, ref string, err error) {
	unknownTotal.Add(1)
	b, _ := json.Marshal(map[string]string{"event": "commit_outcome_unknown", "op": op, "ref": ref, "error": err.Error()})
	log.Print(string(b))
}
