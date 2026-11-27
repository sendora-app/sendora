// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "context"

// downloads.ip holds the recipient address of a download start. Nothing reads
// it back (the owner's download history shows times and files only), so it is
// stored only while the audit_log_ip setting is on (see downloadResponse in
// internal/app/shares.go) and rows are kept for 90 days.

// migrateDownloadIP blanks stored download addresses while audit_log_ip is off
// (a missing setting counts as off, the default). Additive and idempotent: it
// changes no schema and runs again harmlessly at every start.
func (s *Store) migrateDownloadIP() error { return s.BlankDownloadIPs() }

// BlankDownloadIPs empties downloads.ip unless audit_log_ip is on.
func (s *Store) BlankDownloadIPs() error {
	return s.Repos().Downloads().BlankAddressesUnlessLogged(context.Background())
}
