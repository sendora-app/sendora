// SPDX-License-Identifier: AGPL-3.0-or-later

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Backend kinds.
const (
	KindLocal = "local"
	KindS3    = "s3"
	KindAzure = "azure"
	KindGCS   = "gcs"
	// KindNone: no storage at all (a tenant in multi-tenant mode whose storage
	// is not set up yet). It cannot be opened; uploads are refused.
	KindNone = "none"
)

// ErrNotConfigured is returned for KindNone.
var ErrNotConfigured = errors.New("no storage is set up yet")

// Credential modes.
const (
	S3AuthStatic         = "static"          // access key + secret key
	S3AuthDefault        = "default"         // AWS default chain: env, shared files, IRSA/web identity, ECS, EC2
	AzureAuthSharedKey   = "shared_key"      // account key
	AzureAuthSAS         = "sas"             // SAS token
	AzureAuthIdentity    = "identity"        // DefaultAzureCredential: workload/managed identity, env, CLI
	GCSAuthServiceAcct   = "service_account" // service-account JSON key
	GCSAuthDefault       = "default"         // ADC: workload identity, metadata server, GOOGLE_APPLICATION_CREDENTIALS
	GCSAuthNone          = "none"            // only for an emulator endpoint (tests)
	defaultGCSEndpoint   = "https://storage.googleapis.com"
	defaultAzureEndpoint = "https://%s.blob.core.windows.net/"
)

// Config describes one storage location. Secrets are part of it: the database
// (SQLCipher) keeps a copy per location so files stay readable after the
// settings move on to another bucket or backend.
type Config struct {
	Backend string `json:"backend"`
	Prefix  string `json:"prefix,omitempty"`

	S3Endpoint  string `json:"s3_endpoint,omitempty"`
	S3Region    string `json:"s3_region,omitempty"`
	S3Bucket    string `json:"s3_bucket,omitempty"`
	S3PathStyle bool   `json:"s3_path_style,omitempty"`
	S3Auth      string `json:"s3_auth,omitempty"`
	S3AccessKey string `json:"s3_access_key,omitempty"`
	S3SecretKey string `json:"s3_secret_key,omitempty"`

	AzureAccount    string `json:"azure_account,omitempty"`
	AzureContainer  string `json:"azure_container,omitempty"`
	AzureEndpoint   string `json:"azure_endpoint,omitempty"`
	AzureAuth       string `json:"azure_auth,omitempty"`
	AzureAccountKey string `json:"azure_account_key,omitempty"`
	AzureSASToken   string `json:"azure_sas_token,omitempty"`

	GCSBucket          string `json:"gcs_bucket,omitempty"`
	GCSEndpoint        string `json:"gcs_endpoint,omitempty"`
	GCSAuth            string `json:"gcs_auth,omitempty"`
	GCSCredentialsJSON string `json:"gcs_credentials_json,omitempty"`

	// TenantManaged marks a configuration a tenant administrator entered in
	// multi-tenant mode (not the platform): no ambient credentials, and its
	// connections go through the tenant's network guard (store.Backends.Guard).
	TenantManaged bool `json:"tenant_managed,omitempty"`

	// LocalRoot is the directory of the local backend (the data directory).
	LocalRoot string `json:"-"`
	// DialContext, when set, makes every connection of the backend (including
	// token requests) through it: the SSRF guard of internal/netguard.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error) `json:"-"`
}

// ValidateTenantManaged adds the rules for storage a tenant administrator
// configures in multi-tenant mode: only explicit credentials. The ambient
// credentials of the process (AWS default chain and IRSA, Azure managed or
// workload identity, Google application default credentials) belong to the
// platform and could reach the platform's buckets or other tenants' prefixes.
func (c Config) ValidateTenantManaged() error {
	switch c.Backend {
	case KindS3:
		if c.S3Auth != S3AuthStatic {
			return errors.New("use an access key and secret key: the server's own (default) credentials are not available to organisations")
		}
	case KindAzure:
		if c.AzureAuth != AzureAuthSharedKey && c.AzureAuth != AzureAuthSAS {
			return errors.New("use an account key or SAS token: the server's managed identity is not available to organisations")
		}
	case KindGCS:
		if c.GCSAuth != GCSAuthServiceAcct {
			return errors.New("use a service account JSON key: the server's default credentials are not available to organisations")
		}
	}
	return nil
}

// Endpoint returns the endpoint URL the backend connects to: the configured
// one, or the provider's public default.
func (c Config) Endpoint() string {
	switch c.Backend {
	case KindS3:
		if c.S3Endpoint == "" {
			return "https://s3." + c.S3Region + ".amazonaws.com"
		}
		return c.S3Endpoint
	case KindAzure:
		return c.azureServiceURL()
	case KindGCS:
		return c.gcsEndpoint()
	}
	return ""
}

// Overlaps reports whether c and o can reach the same objects: the same
// service and bucket or container, and one prefix contains the other.
func (c Config) Overlaps(o Config) bool {
	if c.Backend != o.Backend || c.Backend == KindLocal || c.Backend == "" {
		return false
	}
	strip := func(x Config) string { x.Prefix = ""; return x.Identity() }
	if strip(c) != strip(o) {
		return false
	}
	return strings.HasPrefix(c.Prefix, o.Prefix) || strings.HasPrefix(o.Prefix, c.Prefix)
}

// WithPrefix returns c with sub appended to its prefix (for example a tenant's
// own folder inside the platform's bucket).
func (c Config) WithPrefix(sub string) Config {
	c.Prefix = NormalizePrefix(c.Prefix + sub)
	return c
}

// Identity is the canonical, secret-free description of where objects live.
// Two configurations with the same identity reach the same objects, so a
// location keeps its identity when only its credentials change.
func (c Config) Identity() string {
	switch c.Backend {
	case KindS3:
		ep := c.S3Endpoint
		if ep == "" {
			ep = "aws"
		}
		return "s3|" + ep + "|" + c.S3Region + "|" + c.S3Bucket + "|" + c.Prefix
	case KindAzure:
		return "azure|" + c.azureServiceURL() + "|" + c.AzureContainer + "|" + c.Prefix
	case KindGCS:
		return "gcs|" + c.gcsEndpoint() + "|" + c.GCSBucket + "|" + c.Prefix
	case KindNone:
		return KindNone
	}
	return KindLocal
}

// Describe is a short human-readable location for screens and logs (no secrets).
func (c Config) Describe() string {
	switch c.Backend {
	case KindS3:
		ep := c.S3Endpoint
		if ep == "" {
			ep = "AWS S3"
		}
		return fmt.Sprintf("s3://%s/%s (%s, %s)", c.S3Bucket, c.Prefix, ep, c.S3Region)
	case KindAzure:
		return fmt.Sprintf("azure://%s/%s/%s", c.AzureAccount, c.AzureContainer, c.Prefix)
	case KindGCS:
		return fmt.Sprintf("gs://%s/%s", c.GCSBucket, c.Prefix)
	case KindNone:
		return "not set up"
	}
	return "local data directory"
}

// Public returns c without credentials (for the admin screen and audit).
func (c Config) Public() Config {
	c.S3SecretKey, c.AzureAccountKey, c.AzureSASToken, c.GCSCredentialsJSON = "", "", "", ""
	return c
}

// Marshal and Unmarshal are the database form of a location.
func (c Config) Marshal() (string, error) {
	b, err := json.Marshal(c)
	return string(b), err
}

func Unmarshal(s string) (Config, error) {
	var c Config
	err := json.Unmarshal([]byte(s), &c)
	return c, err
}

func (c Config) azureServiceURL() string {
	if c.AzureEndpoint != "" {
		return strings.TrimRight(c.AzureEndpoint, "/") + "/"
	}
	return fmt.Sprintf(defaultAzureEndpoint, c.AzureAccount)
}

func (c Config) gcsEndpoint() string {
	if c.GCSEndpoint != "" {
		return strings.TrimRight(c.GCSEndpoint, "/")
	}
	return defaultGCSEndpoint
}

// Validate checks a complete configuration (all fields of its backend).
func (c Config) Validate() error {
	if err := ValidatePrefix(c.Prefix); err != nil {
		return err
	}
	switch c.Backend {
	case KindLocal, "":
		return nil
	case KindNone:
		return ErrNotConfigured
	case KindS3:
		if err := ValidateS3Bucket(c.S3Bucket); err != nil {
			return err
		}
		if err := ValidateRegion(c.S3Region); err != nil {
			return err
		}
		if c.S3Region == "" {
			return errors.New("S3 region is required (use us-east-1 or auto when the service ignores it)")
		}
		if err := ValidateEndpoint(c.S3Endpoint); err != nil {
			return err
		}
		switch c.S3Auth {
		case S3AuthStatic:
			if c.S3AccessKey == "" || c.S3SecretKey == "" {
				return errors.New("S3 access key and secret key are required for static credentials")
			}
		case S3AuthDefault:
		default:
			return errors.New("S3 credentials must be static or default")
		}
	case KindAzure:
		if c.AzureEndpoint == "" {
			if err := ValidateAzureAccount(c.AzureAccount); err != nil {
				return err
			}
		} else if err := ValidateEndpoint(c.AzureEndpoint); err != nil {
			return err
		}
		if err := ValidateAzureContainer(c.AzureContainer); err != nil {
			return err
		}
		switch c.AzureAuth {
		case AzureAuthSharedKey:
			if c.AzureAccount == "" || c.AzureAccountKey == "" {
				return errors.New("Azure storage account and account key are required for shared key authentication")
			}
		case AzureAuthSAS:
			if c.AzureSASToken == "" {
				return errors.New("an Azure SAS token is required for SAS authentication")
			}
		case AzureAuthIdentity:
		default:
			return errors.New("Azure authentication must be shared_key, sas or identity")
		}
	case KindGCS:
		if err := ValidateGCSBucket(c.GCSBucket); err != nil {
			return err
		}
		if err := ValidateEndpoint(c.GCSEndpoint); err != nil {
			return err
		}
		switch c.GCSAuth {
		case GCSAuthServiceAcct:
			if c.GCSCredentialsJSON == "" {
				return errors.New("a service account JSON key is required for service account authentication")
			}
		case GCSAuthDefault:
		case GCSAuthNone:
			if c.GCSEndpoint == "" {
				return errors.New("GCS authentication none is only allowed with a custom (emulator) endpoint")
			}
		default:
			return errors.New("GCS authentication must be service_account or default")
		}
	default:
		return errors.New("storage backend must be local, s3, azure or gcs")
	}
	return nil
}

// Open returns the backend described by c.
func Open(ctx context.Context, c Config) (Backend, error) {
	if c.Backend == KindNone {
		return nil, ErrNotConfigured
	}
	if c.Backend == KindLocal || c.Backend == "" {
		return NewLocal(c.LocalRoot)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	switch c.Backend {
	case KindS3:
		return newS3(ctx, c)
	case KindAzure:
		return newAzure(c)
	case KindGCS:
		return newGCS(ctx, c)
	}
	return nil, errors.New("unknown storage backend")
}

// ---------- field validation (shared by the settings screen and the configuration loader) ----------

var (
	s3BucketRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	ipLikeRe         = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	regionRe         = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
	azureAccountRe   = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
	azureContainerRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9]|-[a-z0-9]){2,62}$`)
	gcsBucketRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$`)
	prefixRe         = regexp.MustCompile(`^[A-Za-z0-9._/-]*$`)
)

// ValidateS3Bucket follows the S3 bucket naming rules (also used by MinIO, R2,
// Wasabi and B2's S3 API).
func ValidateS3Bucket(b string) error {
	if b == "" {
		return errors.New("S3 bucket is required")
	}
	if !s3BucketRe.MatchString(b) || strings.Contains(b, "..") || strings.Contains(b, ".-") || strings.Contains(b, "-.") || ipLikeRe.MatchString(b) || strings.HasPrefix(b, "xn--") {
		return errors.New("invalid S3 bucket name (3-63 lowercase letters, digits, dots and hyphens)")
	}
	return nil
}

func ValidateRegion(r string) error {
	if r != "" && !regionRe.MatchString(r) {
		return errors.New("invalid S3 region")
	}
	return nil
}

func ValidateAzureAccount(a string) error {
	if !azureAccountRe.MatchString(a) {
		return errors.New("invalid Azure storage account name (3-24 lowercase letters and digits)")
	}
	return nil
}

func ValidateAzureContainer(c string) error {
	if !azureContainerRe.MatchString(c) {
		return errors.New("invalid Azure container name (3-63 lowercase letters, digits and single hyphens)")
	}
	return nil
}

func ValidateGCSBucket(b string) error {
	if b == "" {
		return errors.New("GCS bucket is required")
	}
	if !gcsBucketRe.MatchString(b) || strings.Contains(b, "..") || ipLikeRe.MatchString(b) || strings.HasPrefix(b, "goog") || (len(b) > 63 && !strings.Contains(b, ".")) {
		return errors.New("invalid GCS bucket name (3-63 lowercase letters, digits, hyphens, underscores and dots)")
	}
	for _, part := range strings.Split(b, ".") {
		if len(part) > 63 || part == "" {
			return errors.New("invalid GCS bucket name (3-63 lowercase letters, digits, hyphens, underscores and dots)")
		}
	}
	return nil
}

// NormalizePrefix trims slashes and spaces and ends a non-empty prefix with "/".
func NormalizePrefix(p string) string {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "" {
		return ""
	}
	return p + "/"
}

// ValidatePrefix accepts a normalized prefix of safe characters.
func ValidatePrefix(p string) error {
	if p == "" {
		return nil
	}
	if len(p) > 200 || !prefixRe.MatchString(p) || p != NormalizePrefix(p) || strings.Contains(p, "//") {
		return errors.New("invalid storage prefix (letters, digits, '.', '_', '-' and '/' only, at most 200 characters)")
	}
	for _, part := range strings.Split(strings.TrimSuffix(p, "/"), "/") {
		if part == "." || part == ".." {
			return errors.New("invalid storage prefix")
		}
	}
	return nil
}

// ValidateEndpoint accepts an empty endpoint (the provider's default), an
// https URL, or an http URL whose host is on this machine or a private
// network (MinIO, Azurite or fake-gcs-server next to Sendora): loopback and
// private addresses, single-label names and the cluster-internal suffixes
// .svc, .cluster.local, .local and .internal.
func ValidateEndpoint(e string) error {
	if e == "" {
		return nil
	}
	u, err := url.Parse(e)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(e) > 300 {
		return errors.New("invalid storage endpoint (expected https://host[:port][/path])")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if PrivateHost(u.Hostname()) {
			return nil
		}
		return errors.New("storage endpoint must use https (http is only allowed for localhost and private networks)")
	}
	return errors.New("storage endpoint must use https")
}

// PrivateHost reports whether host is a loopback/private address or an
// internal host name.
func PrivateHost(host string) bool {
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "localhost" || !strings.Contains(h, ".") {
		return true
	}
	for _, suffix := range []string{".localhost", ".svc", ".cluster.local", ".local", ".internal"} {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}
