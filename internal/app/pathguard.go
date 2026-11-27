// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"errors"
	"path/filepath"
	"strings"
)

var errUnsafePath = errors.New("unsafe path")

// localJoin joins a trusted root directory with an untrusted, relative name.
// The name must be local (no absolute path, no volume, no ".." escape, not
// empty) and may not contain ".." at all, so the result always stays under
// root. The guard is written in the early-return form static analysers
// recognise as a path-traversal barrier.
func localJoin(root, name string) (string, error) {
	if strings.Contains(name, "..") || !filepath.IsLocal(name) {
		return "", errUnsafePath
	}
	return filepath.Join(root, name), nil
}
