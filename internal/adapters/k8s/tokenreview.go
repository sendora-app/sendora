// SPDX-License-Identifier: AGPL-3.0-or-later

package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// TokenReviewer implements ports.TokenReviewer with the authentication.k8s.io
// TokenReview API. The controller's ServiceAccount needs create on
// tokenreviews.authentication.k8s.io (cluster scope).
type TokenReviewer struct {
	base      string
	client    *http.Client
	tokenFile string
}

// TokenReviewConfig configures a TokenReviewer; empty fields mean in-cluster.
type TokenReviewConfig struct {
	APIServer         string
	TokenFile, CAFile string
	Client            *http.Client
}

// NewTokenReviewer prepares the client of the API server.
func NewTokenReviewer(cfg TokenReviewConfig) (*TokenReviewer, error) {
	if cfg.TokenFile == "" {
		cfg.TokenFile = saTokenFile
	}
	if cfg.CAFile == "" {
		cfg.CAFile = saCAFile
	}
	r := &TokenReviewer{base: cfg.APIServer, client: cfg.Client, tokenFile: cfg.TokenFile}
	if r.base == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, errors.New("tokenreview: not running in a cluster (KUBERNETES_SERVICE_HOST/PORT unset) and no API server configured")
		}
		r.base = "https://" + net.JoinHostPort(host, port)
	}
	if r.client == nil {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("tokenreview: API server CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("tokenreview: API server CA file holds no certificate")
		}
		r.client = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}}
	}
	return r, nil
}

type tokenReview struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Token     string   `json:"token"`
		Audiences []string `json:"audiences,omitempty"`
	} `json:"spec"`
	Status struct {
		Authenticated bool     `json:"authenticated"`
		Audiences     []string `json:"audiences"`
		Error         string   `json:"error"`
		User          struct {
			Username string              `json:"username"`
			Extra    map[string][]string `json:"extra"`
		} `json:"user"`
	} `json:"status"`
}

// Review implements ports.TokenReviewer. The token is accepted only when the
// API server authenticates it for audience.
func (r *TokenReviewer) Review(ctx context.Context, token, audience string) (ports.Identity, error) {
	var in tokenReview
	in.APIVersion, in.Kind = "authentication.k8s.io/v1", "TokenReview"
	in.Spec.Token, in.Spec.Audiences = token, []string{audience}
	body, err := json.Marshal(in)
	if err != nil {
		return ports.Identity{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.base+"/apis/authentication.k8s.io/v1/tokenreviews", bytes.NewReader(body))
	if err != nil {
		return ports.Identity{}, err
	}
	tok, err := os.ReadFile(r.tokenFile) // re-read: projected tokens rotate
	if err != nil {
		return ports.Identity{}, fmt.Errorf("tokenreview: service account token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return ports.Identity{}, fmt.Errorf("tokenreview: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return ports.Identity{}, fmt.Errorf("tokenreview: %s", resp.Status)
	}
	var out tokenReview
	if err := json.Unmarshal(data, &out); err != nil {
		return ports.Identity{}, fmt.Errorf("tokenreview: %w", err)
	}
	if !out.Status.Authenticated || out.Status.User.Username == "" {
		return ports.Identity{}, errors.New("tokenreview: token not authenticated")
	}
	// The API server returns the audiences that matched; require ours.
	ok := false
	for _, a := range out.Status.Audiences {
		ok = ok || a == audience
	}
	if !ok {
		return ports.Identity{}, errors.New("tokenreview: token not valid for the audience")
	}
	id := ports.Identity{User: out.Status.User.Username}
	if pod := out.Status.User.Extra["authentication.kubernetes.io/pod-name"]; len(pod) > 0 {
		id.Pod = pod[0]
	}
	return id, nil
}

// PodNamespace is the namespace of the pod's service account.
func PodNamespace() (string, error) {
	b, err := os.ReadFile(saNamespaceFile)
	if err != nil {
		return "", fmt.Errorf("namespace: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}
