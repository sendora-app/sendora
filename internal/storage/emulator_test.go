// SPDX-License-Identifier: AGPL-3.0-or-later

package storage_test

// Backend tests against real services. They run only when the variables
// below are set, so `go test ./...` passes without Docker or cloud accounts:
//
//	S3 (MinIO):        SENDORA_TEST_S3_ENDPOINT, SENDORA_TEST_S3_ACCESS_KEY,
//	                   SENDORA_TEST_S3_SECRET_KEY, SENDORA_TEST_S3_BUCKET
//	Azure (Azurite or  SENDORA_TEST_AZURE_ACCOUNT, SENDORA_TEST_AZURE_CONTAINER,
//	a real account):   SENDORA_TEST_AZURE_KEY or SENDORA_TEST_AZURE_SAS,
//	                   SENDORA_TEST_AZURE_ENDPOINT (optional; Azurite:
//	                   http://127.0.0.1:10000/devstoreaccount1)
//	GCS (fake-gcs-     SENDORA_TEST_GCS_ENDPOINT, SENDORA_TEST_GCS_BUCKET
//	server):
//
// CI starts MinIO, Azurite and fake-gcs-server as service containers
// (.github/workflows/ci.yml, job "storage").

import (
	"context"
	"os"
	"testing"

	. "github.com/sendora-app/sendora/internal/storage"
	"github.com/sendora-app/sendora/internal/storage/storagetest"
)

// TestS3Config etc. return the emulator configuration from the environment
// (ok false when it is not set). Exported to the app package's e2e tests
// through storagetest would create an import cycle, so the app tests read
// the same variables themselves.

func s3TestConfig(t *testing.T) (Config, bool) {
	ep := os.Getenv("SENDORA_TEST_S3_ENDPOINT")
	if ep == "" {
		return Config{}, false
	}
	return Config{Backend: KindS3, S3Endpoint: ep, S3Region: "us-east-1", S3Bucket: envOr("SENDORA_TEST_S3_BUCKET", "sendora-test"),
		S3PathStyle: true, S3Auth: S3AuthStatic, S3AccessKey: os.Getenv("SENDORA_TEST_S3_ACCESS_KEY"), S3SecretKey: os.Getenv("SENDORA_TEST_S3_SECRET_KEY"),
		Prefix: "storage-test/"}, true
}

func azureTestConfig(t *testing.T) (Config, bool) {
	acct := os.Getenv("SENDORA_TEST_AZURE_ACCOUNT")
	if acct == "" {
		return Config{}, false
	}
	c := Config{Backend: KindAzure, AzureAccount: acct, AzureContainer: envOr("SENDORA_TEST_AZURE_CONTAINER", "sendora-test"),
		AzureEndpoint: os.Getenv("SENDORA_TEST_AZURE_ENDPOINT"), Prefix: "storage-test/"}
	switch {
	case os.Getenv("SENDORA_TEST_AZURE_KEY") != "":
		c.AzureAuth, c.AzureAccountKey = AzureAuthSharedKey, os.Getenv("SENDORA_TEST_AZURE_KEY")
	case os.Getenv("SENDORA_TEST_AZURE_SAS") != "":
		c.AzureAuth, c.AzureSASToken = AzureAuthSAS, os.Getenv("SENDORA_TEST_AZURE_SAS")
	default:
		c.AzureAuth = AzureAuthIdentity
	}
	return c, true
}

func gcsTestConfig(t *testing.T) (Config, bool) {
	ep := os.Getenv("SENDORA_TEST_GCS_ENDPOINT")
	if ep == "" {
		return Config{}, false
	}
	return Config{Backend: KindGCS, GCSEndpoint: ep, GCSBucket: envOr("SENDORA_TEST_GCS_BUCKET", "sendora-test"), GCSAuth: GCSAuthNone, Prefix: "storage-test/"}, true
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func TestS3Emulator(t *testing.T) {
	c, ok := s3TestConfig(t)
	if !ok {
		t.Skip("SENDORA_TEST_S3_ENDPOINT not set")
	}
	ctx := context.Background()
	b, err := Open(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateBucket(ctx, b); err != nil {
		t.Fatal(err)
	}
	storagetest.Run(t, b, storagetest.Options{})
	// No multipart upload may be left behind by the failure tests.
	if n, err := S3PendingUploads(ctx, b); err != nil || n != 0 {
		t.Fatalf("%d multipart uploads left behind (%v)", n, err)
	}
	// Wrong credentials fail the probe.
	bad := c
	bad.S3SecretKey = "wrong-secret"
	bb, _ := Open(ctx, bad)
	if err := Probe(ctx, bb); err == nil {
		t.Fatal("probe passed with a wrong secret key")
	}
}

func TestAzureBlob(t *testing.T) {
	c, ok := azureTestConfig(t)
	if !ok {
		t.Skip("SENDORA_TEST_AZURE_ACCOUNT not set")
	}
	ctx := context.Background()
	b, err := Open(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if c.AzureAuth == AzureAuthSharedKey {
		if err := CreateBucket(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	storagetest.Run(t, b, storagetest.Options{})
	if c.AzureAuth == AzureAuthSharedKey {
		bad := c
		bad.AzureAccountKey = "d3Jvbmcta2V5LXdyb25nLWtleS13cm9uZy1rZXktd3Jvbmcta2V5LXdyb25nLWtleQ=="
		bb, _ := Open(ctx, bad)
		if err := Probe(ctx, bb); err == nil {
			t.Fatal("probe passed with a wrong account key")
		}
	}
}

func TestGCSEmulator(t *testing.T) {
	c, ok := gcsTestConfig(t)
	if !ok {
		t.Skip("SENDORA_TEST_GCS_ENDPOINT not set")
	}
	ctx := context.Background()
	b, err := Open(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateBucket(ctx, b); err != nil {
		t.Fatal(err)
	}
	storagetest.Run(t, b, storagetest.Options{})
}
