// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// defaultHashCost is hashCost as the program starts with it, before TestMain
// lowers it.
var defaultHashCost = hashCost

// TestMain lowers the bcrypt cost: hundreds of tests hash passwords, and at
// cost 12 under -race the suite outgrows the CI time limit. The production cost
// is checked by TestPasswordHashesUseCostTwelveAndUpgrade, which restores it.
func TestMain(m *testing.M) {
	hashCost = bcrypt.MinCost
	os.Exit(m.Run())
}
