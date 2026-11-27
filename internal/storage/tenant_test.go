// SPDX-License-Identifier: AGPL-3.0-or-later

package storage

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestTenantManagedRulesAndOverlap(t *testing.T) {
	s3 := Config{Backend: KindS3, S3Region: "eu-west-1", S3Bucket: "b", S3Auth: S3AuthStatic, S3AccessKey: "a", S3SecretKey: "s", S3Endpoint: "https://s3.example.com"}
	if err := s3.ValidateTenantManaged(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []Config{
		{Backend: KindS3, S3Auth: S3AuthDefault},
		{Backend: KindAzure, AzureAuth: AzureAuthIdentity},
		{Backend: KindGCS, GCSAuth: GCSAuthDefault},
		{Backend: KindGCS, GCSAuth: GCSAuthNone},
	} {
		if c.ValidateTenantManaged() == nil {
			t.Fatalf("ambient credentials accepted: %+v", c)
		}
	}
	a := s3.WithPrefix("tenants/a/")
	b := s3.WithPrefix("tenants/b/")
	root := s3.WithPrefix("tenants/")
	other := s3
	other.S3Bucket = "c"
	if a.Overlaps(b) || !a.Overlaps(root) || !root.Overlaps(b) || a.Overlaps(other) {
		t.Fatal("overlap rules")
	}
	if got := (Config{Backend: KindS3, S3Region: "eu-west-1"}).Endpoint(); got != "https://s3.eu-west-1.amazonaws.com" {
		t.Fatal(got)
	}
	// TenantManaged survives the database form; DialContext does not.
	a.TenantManaged = true
	a.DialContext = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("x") }
	js, _ := a.Marshal()
	back, _ := Unmarshal(js)
	if !back.TenantManaged || back.DialContext != nil || back.Identity() != a.Identity() {
		t.Fatalf("round trip %+v", back.Public())
	}
}

// A configuration with DialContext connects only through it (the SSRF guard).
func TestDialContextIsUsed(t *testing.T) {
	called := false
	c := Config{Backend: KindS3, S3Region: "us-east-1", S3Bucket: "bucket", S3Auth: S3AuthStatic, S3AccessKey: "a", S3SecretKey: "s",
		S3Endpoint: "https://s3.example.com", S3PathStyle: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			called = true
			return nil, errors.New("refused by guard")
		}}
	if tr := httpTransport(c); tr.Proxy != nil || tr.DialContext == nil {
		t.Fatal("guarded transport must not use a proxy")
	}
	b, err := Open(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if err := Probe(context.Background(), b); err == nil || !called {
		t.Fatalf("probe did not go through the dialer: %v", err)
	}
}
