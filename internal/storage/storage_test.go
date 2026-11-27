// SPDX-License-Identifier: AGPL-3.0-or-later

package storage_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sendora-app/sendora/internal/storage"
	"github.com/sendora-app/sendora/internal/storage/storagetest"
)

func TestLocalConformance(t *testing.T) {
	b, err := storage.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	storagetest.Run(t, b, storagetest.Options{Large: 3 << 20})
}

func TestFileKeys(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		k, err := storage.NewFileKey()
		if err != nil || !storage.ValidFileKey(k) || seen[k] {
			t.Fatalf("key %q %v", k, err)
		}
		seen[k] = true
	}
	for _, k := range []string{"files/../backups/x", "backups/sendora.db", "files/ABC", "files/" + strings.Repeat("a", 31), "probe/x"} {
		if storage.ValidFileKey(k) {
			t.Fatalf("%q accepted", k)
		}
	}
}

func TestValidation(t *testing.T) {
	good := map[string]func(string) error{
		"my-bucket.files":  storage.ValidateS3Bucket,
		"abc":              storage.ValidateS3Bucket,
		"sendoraprod01":    storage.ValidateAzureAccount,
		"files-01":         storage.ValidateAzureContainer,
		"my_bucket-1":      storage.ValidateGCSBucket,
		"tenants/acme/":    storage.ValidatePrefix,
		"":                 storage.ValidatePrefix,
		"https://s3.x.com": storage.ValidateEndpoint,
	}
	for v, f := range good {
		if err := f(v); err != nil {
			t.Errorf("%q: %v", v, err)
		}
	}
	bad := map[string]func(string) error{
		"My-Bucket":                 storage.ValidateS3Bucket,
		"ab":                        storage.ValidateS3Bucket,
		"192.168.1.1":               storage.ValidateS3Bucket,
		"a..b":                      storage.ValidateS3Bucket,
		"UPPER":                     storage.ValidateAzureAccount,
		"has-dash":                  storage.ValidateAzureAccount,
		"a--b":                      storage.ValidateAzureContainer,
		"-ab":                       storage.ValidateAzureContainer,
		"googbucket":                storage.ValidateGCSBucket,
		"../x/":                     storage.ValidatePrefix,
		"a b/":                      storage.ValidatePrefix,
		"noslash":                   storage.ValidatePrefix,
		"ftp://x":                   storage.ValidateEndpoint,
		"http://s3.aws.com":         storage.ValidateEndpoint,
		"https://user:pw@x.example": storage.ValidateEndpoint,
	}
	for v, f := range bad {
		if err := f(v); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
	for _, e := range []string{"http://localhost:9000", "http://127.0.0.1:10000/devstoreaccount1", "http://minio:9000", "http://10.1.2.3:9000", "http://minio.storage.svc.cluster.local:9000", "http://[::1]:9000"} {
		if err := storage.ValidateEndpoint(e); err != nil {
			t.Errorf("%s: %v", e, err)
		}
	}
}

func TestNormalizeSettings(t *testing.T) {
	for _, tc := range []struct{ key, in, want string }{
		{"storage_s3_prefix", " /tenants/acme ", "tenants/acme/"},
		{"storage_s3_endpoint", "https://s3.example.com/", "https://s3.example.com"},
		{"storage_azure_sas_token", "?sv=2024&sig=x", "sv=2024&sig=x"},
		{"storage_backend", "s3", "s3"},
	} {
		got, owned, err := storage.NormalizeSetting(tc.key, tc.in)
		if err != nil || !owned || got != tc.want {
			t.Errorf("%s(%q) = %q %v %v", tc.key, tc.in, got, owned, err)
		}
	}
	for _, tc := range [][2]string{{"storage_backend", "ftp"}, {"storage_s3_path_style", "yes"}, {"storage_s3_auth", "x"}, {"storage_gcs_bucket", "Bad"}, {"storage_s3_endpoint", "http://example.com"}} {
		if _, _, err := storage.NormalizeSetting(tc[0], tc[1]); err == nil {
			t.Errorf("%v accepted", tc)
		}
	}
	if _, owned, _ := storage.NormalizeSetting("smtp_host", "x"); owned {
		t.Fatal("non-storage key owned")
	}
}

func TestConfigFromSettingsAndValidate(t *testing.T) {
	vals := map[string]string{}
	for _, s := range storage.Settings {
		vals[s.Key] = s.Default
	}
	get := func(k string) string { return vals[k] }
	if c := storage.FromSettings(get); c.Backend != storage.KindLocal || c.Validate() != nil {
		t.Fatalf("default: %+v", c)
	}
	vals["storage_backend"] = "s3"
	if err := storage.FromSettings(get).Validate(); err == nil {
		t.Fatal("s3 without bucket accepted")
	}
	vals["storage_s3_bucket"], vals["storage_s3_access_key"], vals["storage_s3_secret_key"] = "bucket", "AK", "SK"
	c := storage.FromSettings(get)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Prefix != "sendora/" || c.Public().S3SecretKey != "" || !strings.Contains(c.Identity(), "bucket") || strings.Contains(c.Identity(), "SK") {
		t.Fatalf("config %+v identity %s", c, c.Identity())
	}
	if c.WithPrefix("tenants/acme").Prefix != "sendora/tenants/acme/" {
		t.Fatal(c.WithPrefix("tenants/acme").Prefix)
	}
	vals["storage_s3_auth"] = "default"
	if c := storage.FromSettings(get); c.S3SecretKey != "" || c.Validate() != nil {
		t.Fatal("default chain must not carry static keys")
	}
	vals["storage_backend"], vals["storage_azure_auth"] = "azure", "identity"
	vals["storage_azure_account"], vals["storage_azure_container"] = "acct01", "files"
	if err := storage.FromSettings(get).Validate(); err != nil {
		t.Fatal(err)
	}
	vals["storage_backend"], vals["storage_gcs_auth"], vals["storage_gcs_bucket"] = "gcs", "none", "b1"
	if err := storage.FromSettings(get).Validate(); err == nil {
		t.Fatal("gcs auth none without emulator endpoint accepted")
	}
	cfg := storage.FromSettings(get)
	js, _ := cfg.Marshal()
	back, err := storage.Unmarshal(js)
	if err != nil || back.Identity() != cfg.Identity() {
		t.Fatal("marshal round trip")
	}
}

func TestSecretRetype(t *testing.T) {
	changed := func(keys ...string) func(string) bool {
		return func(k string) bool {
			for _, c := range keys {
				if c == k {
					return true
				}
			}
			return false
		}
	}
	stored := func(string) bool { return true }
	if got := storage.SecretRetypeNeeded(changed("storage_gcs_endpoint"), changed(), stored); got != "storage_gcs_credentials_json" {
		t.Fatalf("got %q", got)
	}
	if got := storage.SecretRetypeNeeded(changed("storage_gcs_endpoint"), changed("storage_gcs_credentials_json"), stored); got != "" {
		t.Fatalf("got %q", got)
	}
	if got := storage.SecretRetypeNeeded(changed("storage_s3_bucket"), changed(), stored); got != "" {
		t.Fatalf("bucket change needs no retype: %q", got)
	}
}

// failingStore fails the first n Put calls of a probe etc.
type countingBackend struct {
	storage.Backend
	opens atomic.Int64
}

func TestProbeDetectsBrokenBackend(t *testing.T) {
	m := storagetest.NewMemory()
	if err := storage.Probe(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if len(m.Keys()) != 0 {
		t.Fatalf("probe left %v", m.Keys())
	}
	m.FailPut.Store(true)
	if err := storage.Probe(context.Background(), m); err == nil {
		t.Fatal("probe passed with failing writes")
	}
	m.FailPut.Store(false)
	m.FailOpen.Store(true)
	if err := storage.Probe(context.Background(), m); err == nil {
		t.Fatal("probe passed with failing reads")
	}
}

func TestLocalRejectsEscapes(t *testing.T) {
	root := t.TempDir()
	b, _ := storage.NewLocal(root)
	for _, k := range []string{"../x", "shares/../../x", "/etc/passwd"} {
		if _, err := b.Path(k); err == nil {
			t.Fatalf("%q accepted", k)
		}
		if err := b.Put(context.Background(), k, bytes.NewReader(nil), 0); err == nil {
			t.Fatalf("put %q accepted", k)
		}
	}
	_ = io.EOF
	_ = errors.New
}
