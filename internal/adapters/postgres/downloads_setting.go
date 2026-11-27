// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"strings"
)

// downloadSettingRepo is the download repository with the one statement that
// compares a setting's value done in Go: the value is sealed, so SQL cannot
// compare it.
type downloadSettingRepo struct{ downloadRepo }

// BlankAddressesUnlessLogged empties downloads.ip unless audit_log_ip is on (a
// missing setting counts as off).
func (r downloadSettingRepo) BlankAddressesUnlessLogged(ctx context.Context) error {
	if on, err := readSetting(ctx, r.q, r.codec, "audit_log_ip"); err == nil && strings.EqualFold(on, "true") {
		return nil
	}
	_, err := r.q.ExecContext(ctx, `UPDATE downloads SET ip='' WHERE ip<>''`)
	return err
}
