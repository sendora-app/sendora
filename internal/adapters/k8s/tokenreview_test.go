// SPDX-License-Identifier: AGPL-3.0-or-later

package k8s

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestTokenReview(t *testing.T) {
	var sawAuth, sawAud string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in tokenReview
		json.NewDecoder(r.Body).Decode(&in)
		sawAuth = r.Header.Get("Authorization")
		sawAud = in.Spec.Audiences[0]
		var out tokenReview
		switch in.Spec.Token {
		case "ok":
			out.Status.Authenticated, out.Status.Audiences = true, []string{"sendora-keys"}
			out.Status.User.Username = "system:serviceaccount:ns:sendora-web"
			out.Status.User.Extra = map[string][]string{"authentication.kubernetes.io/pod-name": {"web-1"}}
		case "wrong-aud":
			out.Status.Authenticated, out.Status.Audiences = true, []string{"https://kubernetes.default.svc"}
			out.Status.User.Username = "system:serviceaccount:ns:sendora-web"
		default:
			out.Status.Error = "invalid"
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer api.Close()
	tf := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tf, []byte("controller-token\n"), 0o600)
	r, err := NewTokenReviewer(TokenReviewConfig{APIServer: api.URL, TokenFile: tf, Client: api.Client()})
	if err != nil {
		t.Fatal(err)
	}
	id, err := r.Review(t.Context(), "ok", "sendora-keys")
	if err != nil || id.User != "system:serviceaccount:ns:sendora-web" || id.Pod != "web-1" {
		t.Fatalf("%+v %v", id, err)
	}
	if sawAuth != "Bearer controller-token" || sawAud != "sendora-keys" {
		t.Fatalf("auth %q audience %q", sawAuth, sawAud)
	}
	for _, tok := range []string{"bad", "wrong-aud"} {
		if _, err := r.Review(t.Context(), tok, "sendora-keys"); err == nil {
			t.Fatalf("token %q accepted", tok)
		}
	}
	api.Close()
	if _, err := r.Review(t.Context(), "ok", "sendora-keys"); err == nil {
		t.Fatal("API server down must fail closed")
	}
}
