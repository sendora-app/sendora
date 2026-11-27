// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// AGPL-3.0 section 13: every user who interacts with Sendora over a network
// must be offered the Corresponding Source of the running version. The footer
// of every page (signed-in, public and share pages, and the platform console)
// shows "Powered by Sendora" and a "Source code" link to SourceURL. There is
// deliberately no setting to switch it off.

// ProjectURL is the upstream project (the "Powered by Sendora" link).
const ProjectURL = "https://github.com/sendora-app/sendora"

var (
	releaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)
	commitHash     = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

	sourceMu  sync.RWMutex
	sourceURL string
)

// ResolveSourceURL returns the link to the source of the running build.
// envURL (SENDORA_SOURCE_URL) wins over buildURL (-ldflags "-X main.sourceURL=…");
// both may contain {version} and {revision}, so forks can point at their own
// repository. An empty or invalid value falls back to the upstream repository:
// the release tag for a release version, else the commit, else the repository.
// The result is never empty. ok is false when a configured value was rejected.
func ResolveSourceURL(version, revision, buildURL, envURL string) (u string, ok bool) {
	ok = true
	for _, tpl := range []string{strings.TrimSpace(envURL), strings.TrimSpace(buildURL)} {
		if tpl == "" {
			continue
		}
		candidate := strings.NewReplacer("{version}", version, "{revision}", revision).Replace(tpl)
		if validSourceURL(candidate) {
			return candidate, ok
		}
		ok = false
	}
	return defaultSourceURL(version, revision), ok
}

func defaultSourceURL(version, revision string) string {
	switch {
	// A "-dev" version (the Dockerfile default between releases) has no tag.
	case releaseVersion.MatchString(version) && !strings.HasSuffix(version, "-dev"):
		return ProjectURL + "/tree/v" + version
	case commitHash.MatchString(revision):
		return ProjectURL + "/tree/" + revision
	default:
		return ProjectURL
	}
}

func validSourceURL(s string) bool {
	if len(s) > 512 || strings.ContainsAny(s, " \t\r\n\"'<>\\") {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
}

// SetSourceURL fixes the source link for this process (main, at start-up).
func SetSourceURL(u string) {
	sourceMu.Lock()
	sourceURL = u
	sourceMu.Unlock()
}

// sourceURLFor is the source link shown in the footer; without SetSourceURL
// (tests, embedding) it is derived from the version.
func sourceURLFor(version string) string {
	sourceMu.RLock()
	u := sourceURL
	sourceMu.RUnlock()
	if u == "" {
		u, _ = ResolveSourceURL(version, "", "", "")
	}
	return u
}
