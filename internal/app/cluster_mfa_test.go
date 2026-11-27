// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/adapters/inproc"
)

// twoReplicas returns two tenant servers of the same tenant that share one
// RateLimiter, as two Cluster web replicas share PostgreSQL.
func twoReplicas() (*Server, *Server) {
	rt := &ClusterRuntime{Limiter: inproc.NewRateLimiter(time.Now)}
	a := &Server{cl: &clusterTenant{rt: rt, tenantID: "tenant-a"}}
	b := &Server{cl: &clusterTenant{rt: rt, tenantID: "tenant-a"}}
	return a, b
}

// TestMFATokenSingleUseAcrossReplicas: an mfa_token completed on one replica
// is spent on every replica (found on the test cluster: replica A accepted a
// token already completed on replica B, with a fresh TOTP code).
func TestMFATokenSingleUseAcrossReplicas(t *testing.T) {
	a, b := twoReplicas()
	exp := time.Now().Add(mfaTokenTTL)
	if !b.spendMFAToken("jti-1", exp) {
		t.Fatal("first spend on B refused")
	}
	if a.spendMFAToken("jti-1", exp) {
		t.Fatal("token spent on B accepted again on A")
	}
	if b.spendMFAToken("jti-1", exp) {
		t.Fatal("token spent on B accepted again on B")
	}
	if !a.spendMFAToken("jti-2", exp) {
		t.Fatal("a different token refused")
	}
	// Another tenant's token with the same jti is independent.
	other := &Server{cl: &clusterTenant{rt: a.cl.rt, tenantID: "tenant-b"}}
	if !other.spendMFAToken("jti-1", exp) {
		t.Fatal("same jti of another tenant refused")
	}
}

// TestMFATokenConcurrentSpendExactlyOnce: replicas racing to complete the
// same token: exactly one wins.
func TestMFATokenConcurrentSpendExactlyOnce(t *testing.T) {
	a, b := twoReplicas()
	exp := time.Now().Add(mfaTokenTTL)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		s := a
		if i%2 == 1 {
			s = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.spendMFAToken("race", exp) {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d replicas completed the same token, want 1", wins.Load())
	}
}

// TestMFATokenSpendWithoutCluster keeps the Community behaviour.
func TestMFATokenSpendWithoutCluster(t *testing.T) {
	s := &Server{}
	exp := time.Now().Add(mfaTokenTTL)
	if !s.spendMFAToken("x", exp) || s.spendMFAToken("x", exp) {
		t.Fatal("single use broken without the cluster runtime")
	}
}

// TestStepUpGrantSharedAcrossReplicas: a step-up confirmed on one replica is
// visible on the other with its original grant time (found on the test
// cluster: replica B asked again right after a confirmation on replica A).
func TestStepUpGrantSharedAcrossReplicas(t *testing.T) {
	a, b := twoReplicas()
	session := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	at := time.Now().Add(-30 * time.Second).Truncate(time.Millisecond)
	if _, ok := b.sharedStepUpAt(7, session.Unix()); ok {
		t.Fatal("grant reported before any confirmation")
	}
	a.shareStepUp(7, session, at)
	got, ok := b.sharedStepUpAt(7, session.Unix())
	if !ok || !got.Equal(at) {
		t.Fatalf("B sees grant %v, %v; want %v", got, ok, at)
	}
	if _, ok := b.sharedStepUpAt(8, session.Unix()); ok {
		t.Fatal("grant of user 7 reported for user 8")
	}
	if _, ok := b.sharedStepUpAt(7, session.Unix()+5); ok {
		t.Fatal("grant reported for another session")
	}
	// A later confirmation moves the grant time forward (blocks never shorten).
	later := at.Add(20 * time.Second)
	b.shareStepUp(7, session, later)
	if got, _ := a.sharedStepUpAt(7, session.Unix()); !got.Equal(later) {
		t.Fatalf("after a second confirmation A sees %v, want %v", got, later)
	}
	// Without the cluster runtime nothing is shared.
	if _, ok := (&Server{}).sharedStepUpAt(7, session.Unix()); ok {
		t.Fatal("grant without a cluster runtime")
	}
}

// TestClusterEnvNotReportedAsTypo: the Cluster flavour's variables and the
// service links of its Services are known; look-alike typos still warn.
func TestClusterEnvNotReportedAsTypo(t *testing.T) {
	for _, n := range []string{"SENDORA_PG_POOLER", "SENDORA_PG_CA_FILE", "SENDORA_POD_NAME", "SENDORA_K8S_API", "SENDORA_LEASE_SECONDS"} {
		if !serverEnvNames[n] {
			t.Errorf("%s is reported as unknown", n)
		}
	}
	for _, n := range []string{"SENDORA_SERVICE_HOST", "SENDORA_WEB_SERVICE_PORT", "SENDORA_WEB_PORT_8080_TCP_ADDR", "SENDORA_CONTROLLER_PORT"} {
		if !k8sServiceLinkRe.MatchString(n) {
			t.Errorf("service link %s not recognised", n)
		}
	}
	for _, n := range []string{"SENDORA_SMPT_PORT", "SENDORA_WEBB_SERVICE_HOST", "SENDORA_WEB_PORTAL"} {
		if k8sServiceLinkRe.MatchString(n) {
			t.Errorf("%s hidden as a service link", n)
		}
	}
}

// TestWebAuthnCeremonyAcrossReplicas: a ceremony begun on replica A finishes
// on replica B, once (found on the test cluster: ceremonies were per replica).
func TestWebAuthnCeremonyAcrossReplicas(t *testing.T) {
	a, b := twoReplicas()
	secret := bytes.Repeat([]byte{3}, 32)
	a.Secret, b.Secret = secret, secret
	ch := bytes.Repeat([]byte{4}, 32)
	id, err := a.waBeginCeremony(waKindRegistration, 9, "", ch)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := b.waTakeCeremony(id, waKindRegistration, 9, ""); !ok || !bytes.Equal(got, ch) {
		t.Fatal("ceremony begun on A refused on B")
	}
	if _, ok := a.waTakeCeremony(id, waKindRegistration, 9, ""); ok {
		t.Fatal("ceremony completed on B completed again on A")
	}
}
