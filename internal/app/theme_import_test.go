// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"strings"
	"testing"
)

func TestBundledThemeCannotBeOverwritten(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	good := map[string]string{}
	for _, key := range themeKeys {
		good[key] = "#123456"
	}
	var bundled Theme
	for _, theme := range e.s.allThemes() {
		if theme.Bundled {
			bundled = theme
			break
		}
	}
	if bundled.ID == 0 {
		t.Fatal("no bundled theme")
	}
	e.want(e.do("POST", "/api/themes", admin, map[string]any{"id": bundled.ID, "name": "Hijacked", "data": good}), 400, "bundled theme not editable")
	for _, theme := range e.s.allThemes() {
		if theme.ID == bundled.ID && (theme.Name != bundled.Name || theme.Data["primary"] != bundled.Data["primary"]) {
			t.Fatal("bundled theme was modified")
		}
	}
}

func TestThemeImportValidation(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	good := map[string]string{}
	for _, key := range themeKeys {
		good[key] = "#123456"
	}
	e.want(e.do("POST", "/api/themes", admin, map[string]any{"name": "Imported", "data": good}), 200, "import")
	for _, bad := range []string{"#12345", "#1234567", "#fff;background:url(x)"} {
		data := map[string]string{}
		for key, value := range good {
			data[key] = value
		}
		data["primary"] = bad
		e.want(e.do("POST", "/api/themes", admin, map[string]any{"name": "Invalid", "data": data}), 400, "invalid color")
	}
	good["extra"] = "#fff"
	e.want(e.do("POST", "/api/themes", admin, map[string]any{"name": "Extra", "data": good}), 400, "unknown color")
	delete(good, "extra")
	for _, name := range []string{"Bad\nName", strings.Repeat("x", 81)} {
		e.want(e.do("POST", "/api/themes", admin, map[string]any{"name": name, "data": good}), 400, "invalid name")
	}
	themes := e.s.allThemes()
	var id int64
	for _, theme := range themes {
		if theme.Name == "Imported" {
			id = theme.ID
		}
	}
	e.want(e.do("POST", "/api/themes", admin, map[string]any{"name": "Second", "data": good}), 200, "second")
	e.want(e.do("POST", "/api/themes", admin, map[string]any{"id": id, "name": "Second", "data": good}), 400, "duplicate update does not panic")
	if id == 0 {
		t.Fatal(fmt.Sprint("missing imported theme"))
	}
}
