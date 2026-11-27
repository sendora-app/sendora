// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sendora-app/sendora/internal/store"
)

func TestConfigSettingsAreAppliedAndLocked(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "smtp")
	os.WriteFile(secret, []byte("from-secret\n"), 0o600)
	t.Setenv("SENDORA_SMTP_HOST", "mail.example.com")
	t.Setenv("SENDORA_SMTP_PASSWORD_FILE", secret)
	t.Setenv("SENDORA_ALLOW_SELF_REGISTRATION", "TRUE")
	t.Setenv("SENDORA_IDLE_LOGOUT_MINUTES", " 30 ")
	e := newEnv(t)
	admin := e.setup()
	for k, want := range map[string]string{"smtp_host": "mail.example.com", "smtp_pass": "from-secret", "allow_self_registration": "true", "idle_logout_minutes": "30"} {
		if got := e.s.St.Setting(k); got != want {
			t.Fatalf("%s = %q, want %q", k, got, want)
		}
	}
	g := e.do("GET", "/api/settings", admin, nil)
	if !strings.Contains(string(g.Body), `"managed_settings":["allow_self_registration","idle_logout_minutes","smtp_host","smtp_pass"]`) {
		t.Fatalf("managed list: %s", g.Body)
	}
	if strings.Contains(string(g.Body), "from-secret") {
		t.Fatal("secret exposed")
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"smtp_host": "mx.other.example"}), 400, "managed setting cannot change")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"smtp_host": "mail.example.com", "smtp_pass": "", "allow_self_registration": true, "show_language_selector": false}), 200, "unchanged managed values plus an unmanaged change")
	if e.s.St.Setting("show_language_selector") != "false" || e.s.St.Setting("smtp_pass") != "from-secret" {
		t.Fatal("save with managed values went wrong")
	}
}

func TestConfigInvalidValueStopsTheServer(t *testing.T) {
	t.Setenv("SENDORA_CLEAN_FILES_DAYS", "-1")
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	legacyTestDefaults(t, st)
	defer st.DB.Close()
	defer func() {
		r := recover()
		if r == nil || !strings.Contains(fmt.Sprint(r), "SENDORA_CLEAN_FILES_DAYS") {
			t.Fatalf("expected a startup error naming the variable, got %v", r)
		}
	}()
	New(st, fstest.MapFS{"index.html": {Data: []byte("x")}}, "test")
}

func TestConfigProviders(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "client")
	os.WriteFile(secret, []byte("s3cr3t"), 0o600)
	t.Setenv("SENDORA_PROVIDER_CORP_TYPE", "entra")
	t.Setenv("SENDORA_PROVIDER_CORP_NAME", "Company login")
	t.Setenv("SENDORA_PROVIDER_CORP_TENANT_ID", "11111111-2222-3333-4444-555555555555")
	t.Setenv("SENDORA_PROVIDER_CORP_CLIENT_ID", "client-id")
	t.Setenv("SENDORA_PROVIDER_CORP_CLIENT_SECRET_FILE", secret)
	t.Setenv("SENDORA_PROVIDER_CORP_ALLOW_REGISTRATION", "true")
	e := newEnv(t)
	admin := e.setup()
	p, err := e.s.providerByUUID("config-corp")
	if err != nil || !p.Managed || p.Name != "Company login" || p.ClientSecret != "s3cr3t" || !p.Enabled || !p.AllowRegistration || p.TrustEmail {
		t.Fatalf("provider from config: %+v %v", p, err)
	}
	e.want(e.do("PUT", fmt.Sprintf("/api/auth-providers/%d", p.ID), admin, map[string]any{"name": "x", "type": "entra", "tenant_id": "11111111-2222-3333-4444-555555555555", "client_id": "client-id"}), 409, "managed provider cannot be edited")
	e.want(e.do("DELETE", fmt.Sprintf("/api/auth-providers/%d", p.ID), admin, nil), 409, "managed provider cannot be deleted")
	if strings.Contains(string(e.do("GET", "/api/auth-providers", admin, nil).Body), "s3cr3t") {
		t.Fatal("client secret exposed")
	}
	// Without the variables the provider becomes editable again (same database).
	for _, k := range []string{"TYPE", "NAME", "TENANT_ID", "CLIENT_ID", "CLIENT_SECRET_FILE", "ALLOW_REGISTRATION"} {
		os.Unsetenv("SENDORA_PROVIDER_CORP_" + k)
	}
	s2 := New(e.s.St, fstest.MapFS{"index.html": {Data: []byte("x")}}, "test")
	ts := httptest.NewServer(s2.Router())
	defer ts.Close()
	p2, _ := s2.providerByUUID("config-corp")
	if p2 == nil || p2.Managed {
		t.Fatal("provider still locked after its configuration was removed")
	}
}

func TestConfigRejectsUnknownProviderVariable(t *testing.T) {
	t.Setenv("SENDORA_PROVIDER_X_COLOUR", "blue")
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	legacyTestDefaults(t, st)
	defer st.DB.Close()
	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "SENDORA_PROVIDER_X_COLOUR") {
			t.Fatalf("expected an error naming the variable, got %v", r)
		}
	}()
	New(st, fstest.MapFS{"index.html": {Data: []byte("x")}}, "test")
}

func TestJWTSecretFromFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "jwt")
	os.WriteFile(p, []byte(strings.Repeat("s", 40)+"\n"), 0o600)
	t.Setenv("JWT_SECRET_FILE", p)
	got, err := JWTSecretFromEnv()
	if err != nil || got != strings.Repeat("s", 40) {
		t.Fatalf("got %q %v", got, err)
	}
	t.Setenv("JWT_SECRET_FILE", filepath.Join(t.TempDir(), "missing"))
	if _, err := JWTSecretFromEnv(); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestConfigWarnsAboutUnknownVariables(t *testing.T) {
	var buf strings.Builder
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	t.Setenv("SENDORA_SMPT_HOST", "typo.example.com")
	t.Setenv("SENDORA_LOCAL_LOGIN_ENABLED", "false")
	t.Setenv("SENDORA_SERVICE_HOST", "x")
	t.Setenv("SENDORA_SERVICE_PORT", "x")
	t.Setenv("SENDORA_SERVICE_PORT_HTTP", "x")
	t.Setenv("SENDORA_PORT", "x")
	t.Setenv("SENDORA_PORT_80_TCP", "x")
	t.Setenv("SENDORA_PORT_80_TCP_PROTO", "x")
	t.Setenv("SENDORA_PORT_80_TCP_PORT", "x")
	t.Setenv("SENDORA_PORT_80_TCP_ADDR", "x")
	newEnv(t)
	out := buf.String()
	if !strings.Contains(out, "SENDORA_SMPT_HOST is not a Sendora setting") {
		t.Fatalf("no warning for a misspelled variable: %s", out)
	}
	if !strings.Contains(out, "local login is switched off") {
		t.Fatalf("no lockout warning: %s", out)
	}
	if strings.Contains(out, "SENDORA_SERVICE_") || strings.Contains(out, "SENDORA_PORT") {
		t.Fatalf("warned about Kubernetes service links: %s", out)
	}
	if strings.Contains(out, "SENDORA_LOCAL_LOGIN_ENABLED is not") {
		t.Fatal("a real setting was reported as unknown")
	}
}
