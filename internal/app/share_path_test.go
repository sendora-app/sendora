// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"net/url"
	"strings"
	"testing"
)

// Browsers (encodeURIComponent) leave ( ) ! ' * unescaped while Go's canonical
// form escapes them; downloads and previews must work for both encodings.
func TestDownloadAndPreviewNamesWithSpecialCharacters(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	png := "\x89PNG\r\n\x1a\n" + strings.Repeat("x", 32)
	made := e.share(admin, map[string]string{"photo (1).png": png, "it's! (a).txt": "hi", "dir/x (2).txt": "deep"}, nil)
	lid := made.S("long_id")
	for _, name := range []string{"it's! (a).txt", "dir/x (2).txt", "photo (1).png"} {
		segments := strings.Split(name, "/")
		browser := make([]string, len(segments))
		canonical := make([]string, len(segments))
		for i, seg := range segments {
			browser[i] = strings.ReplaceAll(url.QueryEscape(seg), "+", "%20")
			for _, c := range []string{"(", ")", "!", "'", "*"} {
				browser[i] = strings.ReplaceAll(browser[i], url.QueryEscape(c), c)
			}
			canonical[i] = (&url.URL{Path: seg}).EscapedPath()
		}
		for _, p := range []string{strings.Join(browser, "/"), strings.Join(canonical, "/")} {
			e.want(e.do("GET", "/api/shares/"+lid+"/download/"+p, "", nil), 200, "download "+p)
		}
	}
	for _, p := range []string{"photo%20(1).png", "photo%20%281%29.png"} {
		e.want(e.do("GET", "/api/shares/"+lid+"/preview/"+p, "", nil), 200, "preview "+p)
	}
}
