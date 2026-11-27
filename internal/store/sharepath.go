// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"errors"
	"path/filepath"
	"regexp"
)

var (
	readableLongID = regexp.MustCompile(`^[a-z]+-[a-z]+-[a-z]+-[1-9][0-9]{6}-[a-z]+-[1-9][0-9]{6}-[a-z]+$`)
	legacyLongID   = regexp.MustCompile(`^[a-f0-9]{16}$`)
)

// ValidLongID reports whether id has one of the two share ID formats Sendora
// ever generated: the readable word/number form or the legacy 16-hex form.
// Anything else (".." or a path) must never reach the filesystem.
func ValidLongID(id string) bool {
	return len(id) <= 128 && (readableLongID.MatchString(id) || legacyLongID.MatchString(id))
}

var errUnsafeSharePath = errors.New("unsafe share storage path")

// ShareDir returns DataDir/shares/<longID> for a validated long ID.
func ShareDir(dataDir, longID string) (string, error) {
	if !ValidLongID(longID) {
		return "", errUnsafeSharePath
	}
	return filepath.Join(dataDir, "shares", longID), nil
}

// SharePath derives a stored file's location from this server's data directory,
// the share's long ID and ONLY the base name of the recorded disk_path. The
// directory part recorded in the database is never trusted, so a crafted or
// relocated database cannot point reads, renames or deletes outside the share's
// own directory.
func SharePath(dataDir, longID, diskPath string) (string, error) {
	dir, err := ShareDir(dataDir, longID)
	if err != nil {
		return "", err
	}
	base := filepath.Base(diskPath)
	if diskPath == "" || base == "." || base == ".." || base == string(filepath.Separator) || base != filepath.Clean(base) {
		return "", errUnsafeSharePath
	}
	return filepath.Join(dir, base), nil
}
