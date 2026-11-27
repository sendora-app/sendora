// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/sendora-app/sendora/internal/ports"
)

const (
	settingRegistrationDomains = "registration_email_domains"
	maxRegistrationDomains     = 50
	maxDomainLength            = 253
)

// normalizeRegistrationDomains turns administrator input (domains separated by
// commas, spaces or newlines) into one lowercase domain per line. Duplicates
// are dropped, the first occurrence keeps its position. Any invalid entry
// rejects the whole input. Empty input means "no restriction".
func normalizeRegistrationDomains(in string) (string, error) {
	fields := strings.FieldsFunc(in, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	seen := make(map[string]bool, len(fields))
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		d := strings.ToLower(f)
		if !validRegistrationDomain(d) {
			return "", fmt.Errorf("invalid registration domain %q: use plain lowercase hostnames such as example.com (no @, wildcard, scheme or path; punycode for international names)", truncateForMessage(f))
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	if len(out) > maxRegistrationDomains {
		return "", fmt.Errorf("too many registration domains: at most %d allowed", maxRegistrationDomains)
	}
	return strings.Join(out, "\n"), nil
}

func truncateForMessage(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}

// validRegistrationDomain accepts a lowercase hostname with at least two
// labels of 1-63 characters from [a-z0-9-], not starting or ending with '-'.
func validRegistrationDomain(d string) bool {
	if len(d) == 0 || len(d) > maxDomainLength {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) < 1 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// emailDomain returns the lowercased text after the last '@'.
func emailDomain(email string) string {
	i := strings.LastIndex(email, "@")
	if i < 0 {
		return ""
	}
	return strings.ToLower(email[i+1:])
}

// domainAllowed reports whether email's domain is in the normalised list.
// An empty list allows everything; matching is exact.
func domainAllowed(list, email string) bool {
	if strings.TrimSpace(list) == "" {
		return true
	}
	d := emailDomain(email)
	if d == "" {
		return false
	}
	for _, l := range strings.Split(list, "\n") {
		if l == d {
			return true
		}
	}
	return false
}

var errRegistrationDomainsCorrupt = errors.New("stored registration domains are invalid")

// registrationDomainList reads and re-validates the stored list. Any read
// error or invalid stored value is returned so callers can fail closed.
func (s *Server) registrationDomainList() (string, error) {
	raw, err := s.St.Repos().Settings().Get(context.Background(), settingRegistrationDomains)
	if err != nil {
		if errors.Is(err, ports.ErrNotFound) {
			return "", nil
		}
		return "", err
	}
	norm, err := normalizeRegistrationDomains(raw)
	if err != nil {
		return "", errRegistrationDomainsCorrupt
	}
	return norm, nil
}

// registrationRestricted is the only registration-domain fact published to
// anonymous clients. A corrupt value counts as restricted (fail closed).
func (s *Server) registrationRestricted() bool {
	list, err := s.registrationDomainList()
	return err != nil || list != ""
}
