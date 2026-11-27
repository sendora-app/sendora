// SPDX-License-Identifier: AGPL-3.0-or-later

package storage

import (
	"errors"
	"fmt"
	"strings"
)

// Setting is one storage setting of Admin -> Storage. Every setting
// also has the variable SENDORA_<KEY> (and SENDORA_<KEY>_FILE).
type Setting struct {
	Key, Default string
	Secret       bool
	Bool         bool
}

// Settings lists the storage settings with their defaults. local stays the
// default backend, so existing installations keep working unchanged.
var Settings = []Setting{
	{Key: "storage_backend", Default: KindLocal},
	{Key: "storage_s3_endpoint"},
	{Key: "storage_s3_region", Default: "us-east-1"},
	{Key: "storage_s3_bucket"},
	{Key: "storage_s3_prefix", Default: "sendora/"},
	{Key: "storage_s3_path_style", Default: "false", Bool: true},
	{Key: "storage_s3_auth", Default: S3AuthStatic},
	{Key: "storage_s3_access_key"},
	{Key: "storage_s3_secret_key", Secret: true},
	{Key: "storage_azure_account"},
	{Key: "storage_azure_container"},
	{Key: "storage_azure_endpoint"},
	{Key: "storage_azure_prefix", Default: "sendora/"},
	{Key: "storage_azure_auth", Default: AzureAuthSharedKey},
	{Key: "storage_azure_account_key", Secret: true},
	{Key: "storage_azure_sas_token", Secret: true},
	{Key: "storage_gcs_bucket"},
	{Key: "storage_gcs_endpoint"},
	{Key: "storage_gcs_prefix", Default: "sendora/"},
	{Key: "storage_gcs_auth", Default: GCSAuthServiceAcct},
	{Key: "storage_gcs_credentials_json", Secret: true},
	{Key: "backup_remote_enabled", Default: "false", Bool: true},
}

// SettingSecret reports whether key is a write-only storage secret.
func SettingSecret(key string) bool {
	for _, s := range Settings {
		if s.Key == key {
			return s.Secret
		}
	}
	return false
}

// IsSetting reports whether key is a storage setting.
func IsSetting(key string) bool {
	for _, s := range Settings {
		if s.Key == key {
			return true
		}
	}
	return false
}

// secretFor lists, per backend, the stored secrets that must be typed again
// when the place they are sent to changes (like the SMTP password).
var secretFor = map[string][]string{
	"storage_s3_secret_key":        {"storage_s3_endpoint", "storage_s3_access_key"},
	"storage_azure_account_key":    {"storage_azure_endpoint", "storage_azure_account"},
	"storage_azure_sas_token":      {"storage_azure_endpoint", "storage_azure_account"},
	"storage_gcs_credentials_json": {"storage_gcs_endpoint"},
}

// SecretRetypeNeeded returns the secret that must be entered again because one
// of the fields that decide where it is sent changes, or "".
func SecretRetypeNeeded(changed func(key string) bool, typed func(key string) bool, stored func(key string) bool) string {
	for secret, fields := range secretFor {
		if typed(secret) || !stored(secret) {
			continue
		}
		for _, f := range fields {
			if changed(f) {
				return secret
			}
		}
	}
	return ""
}

// NormalizeSetting validates one storage setting value and returns its stored
// form. owned is false for keys that are not storage settings.
func NormalizeSetting(key, v string) (norm string, owned bool, err error) {
	var def Setting
	found := false
	for _, s := range Settings {
		if s.Key == key {
			def, found = s, true
		}
	}
	if !found {
		return v, false, nil
	}
	if def.Bool {
		if v != "true" && v != "false" {
			return "", true, fmt.Errorf("%s must be true or false", key)
		}
		return v, true, nil
	}
	if !def.Secret {
		v = strings.TrimSpace(v)
		if strings.ContainsAny(v, "\r\n\t") {
			return "", true, fmt.Errorf("invalid value for %s", key)
		}
	} else if len(v) > 64<<10 {
		return "", true, fmt.Errorf("%s is too long", key)
	}
	switch key {
	case "storage_backend":
		switch v {
		case KindLocal, KindS3, KindAzure, KindGCS:
		default:
			return "", true, errors.New("storage backend must be local, s3, azure or gcs")
		}
	case "storage_s3_endpoint", "storage_azure_endpoint", "storage_gcs_endpoint":
		v = strings.TrimRight(v, "/")
		if err := ValidateEndpoint(v); err != nil {
			return "", true, err
		}
	case "storage_s3_region":
		if err := ValidateRegion(v); err != nil {
			return "", true, err
		}
	case "storage_s3_bucket":
		if v != "" {
			if err := ValidateS3Bucket(v); err != nil {
				return "", true, err
			}
		}
	case "storage_azure_account":
		if v != "" {
			if err := ValidateAzureAccount(v); err != nil {
				return "", true, err
			}
		}
	case "storage_azure_container":
		if v != "" {
			if err := ValidateAzureContainer(v); err != nil {
				return "", true, err
			}
		}
	case "storage_gcs_bucket":
		if v != "" {
			if err := ValidateGCSBucket(v); err != nil {
				return "", true, err
			}
		}
	case "storage_s3_prefix", "storage_azure_prefix", "storage_gcs_prefix":
		v = NormalizePrefix(v)
		if err := ValidatePrefix(v); err != nil {
			return "", true, err
		}
	case "storage_s3_auth":
		if v != S3AuthStatic && v != S3AuthDefault {
			return "", true, errors.New("S3 credentials must be static or default")
		}
	case "storage_azure_auth":
		if v != AzureAuthSharedKey && v != AzureAuthSAS && v != AzureAuthIdentity {
			return "", true, errors.New("Azure authentication must be shared_key, sas or identity")
		}
	case "storage_gcs_auth":
		if v != GCSAuthServiceAcct && v != GCSAuthDefault && v != GCSAuthNone {
			return "", true, errors.New("GCS authentication must be service_account, default or none")
		}
	case "storage_s3_access_key":
		if len(v) > 256 {
			return "", true, errors.New("S3 access key is too long")
		}
	case "storage_azure_sas_token":
		v = strings.TrimPrefix(strings.TrimSpace(v), "?")
	}
	return v, true, nil
}

// FromSettings builds the configuration of the selected backend from the
// stored settings (get returns a setting's value).
func FromSettings(get func(key string) string) Config {
	c := Config{Backend: get("storage_backend")}
	switch c.Backend {
	case KindS3:
		c.Prefix = NormalizePrefix(get("storage_s3_prefix"))
		c.S3Endpoint = get("storage_s3_endpoint")
		c.S3Region = get("storage_s3_region")
		c.S3Bucket = get("storage_s3_bucket")
		c.S3PathStyle = get("storage_s3_path_style") == "true"
		c.S3Auth = get("storage_s3_auth")
		if c.S3Auth == S3AuthStatic {
			c.S3AccessKey = get("storage_s3_access_key")
			c.S3SecretKey = get("storage_s3_secret_key")
		}
	case KindAzure:
		c.Prefix = NormalizePrefix(get("storage_azure_prefix"))
		c.AzureAccount = get("storage_azure_account")
		c.AzureContainer = get("storage_azure_container")
		c.AzureEndpoint = get("storage_azure_endpoint")
		c.AzureAuth = get("storage_azure_auth")
		switch c.AzureAuth {
		case AzureAuthSharedKey:
			c.AzureAccountKey = get("storage_azure_account_key")
		case AzureAuthSAS:
			c.AzureSASToken = get("storage_azure_sas_token")
		}
	case KindGCS:
		c.Prefix = NormalizePrefix(get("storage_gcs_prefix"))
		c.GCSBucket = get("storage_gcs_bucket")
		c.GCSEndpoint = get("storage_gcs_endpoint")
		c.GCSAuth = get("storage_gcs_auth")
		if c.GCSAuth == GCSAuthServiceAcct {
			c.GCSCredentialsJSON = get("storage_gcs_credentials_json")
		}
	default:
		c.Backend = KindLocal
	}
	return c
}
