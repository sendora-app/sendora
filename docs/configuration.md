# Configuration

Environment variables and runtime settings.

[Back to the documentation index](README.md)

## Runtime configuration

| Variable | Local default | Purpose |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | HTTP bind address; Docker sets `0.0.0.0` inside the container. |
| `PORT` | `8080` | HTTP listening port; Docker also defaults to 8080. |
| `DATA_DIR` | `./data` | Database and storage root; Docker sets `/data`. Share files live here too unless an object store is configured (see *Object storage*). |
| `SENDORA_DB_KEY_FILE` | required, no default | Path to the external regular file containing exactly 32 raw key bytes. Owner must be root or the current process UID; no group-write or world permissions. Group-read is allowed for projected `fsGroup` secrets. Never put the key value in an environment variable or command-line argument. |
| `SENDORA_DB_INITIALIZE` | `false` | Explicit `true` permits a new encrypted database only. Disable after private first startup; existing plaintext is never automatically migrated. |
| `APP_URL` | unset | Canonical application URL used for generated links, email links, OAuth callbacks, origin checks, and secure-cookie decisions. |
| `JWT_SECRET` | generated and stored in SQLite | Optional override for the session-signing secret. Must be at least 32 characters with at least 8 distinct ones (Sendora refuses to start otherwise); keep a stable, high-entropy value. `JWT_SECRET_FILE` reads it from a file (Docker/Kubernetes secret) instead. Every `*_FILE` secret (this one, the SMTP password, provider client secrets) must be owned by root or the Sendora user and have no group-write and no world access (for example mode `0400` or `0440`), or Sendora refuses to start; a secret in a plain environment variable is logged as a warning (never the value). |
| `SENDORA_SETUP_CODE` | generated | Optional fixed one-time code for first-run setup (at least 16 characters, not a repeated or sequential pattern), for automated deployments. Without it Sendora generates a code and prints it in the log while no account exists. |
| `SENDORA_VERIFIED_DOWNLOAD_MAX_BYTES` | `17179869184` (16 GiB) | Positive integer byte limit for each temporary verified download snapshot; invalid/nonpositive values fall back to the default. |
| `SENDORA_SOURCE_URL` | the release tag `https://github.com/sendora-app/sendora/tree/v<version>` (commit for development builds) | Target of the **Source code** link shown next to "Powered by Sendora" in the footer of every page (signed-in, sign-in, share pages and the platform console), as required by section 13 of the AGPL. **Forks and modified builds must set it** to the source of the version they run; `{version}` and `{revision}` are filled in (for example `https://git.example.com/acme/files/tree/{revision}`). The same default can be baked in at build time with `-ldflags "-X main.sourceURL=…"` (Docker: `--build-arg SOURCE_URL=…`); the variable wins. Only `http(s)` URLs are accepted; an invalid value logs a warning and the default is used. There is no setting to hide the link or the attribution. |
| `SENDORA_KEY_JOB_CONCURRENCY` | `3` | How many key jobs (re-encryption of a tenant's data after a rotation) one process runs at the same time. A forced rotation for every tenant (platform console) queues one job per tenant; the rest wait for a free slot, so the database pooler and PostgreSQL are not flooded. |
| `SENDORA_KEY_OPS_PER_HOUR` | `10` | How many key operations (rotate, retire, convert files, tenant-key upload/replace/release) a tenant may start per hour (the platform administrator's forced rotations and master key actions have their own budget of the same size, counted per administrator). The tenant budget is per tenant and, in the Cluster flavour, shared by all replicas. It limits what a stolen administrator session can do; raise it only for testing. |
| `SENDORA_TRUSTED_PROXIES` | unset | Comma-separated IPs/CIDRs of reverse proxies whose `X-Forwarded-For` / `X-Forwarded-Proto` headers are believed (for example `10.0.0.0/8,127.0.0.1`). Empty means the TCP peer is the client and forwarded headers are ignored. With proxies configured, the right-most forwarded address that is not itself a trusted proxy is the client address used for rate limits and download records, and `X-Forwarded-Proto: https` marks cookies `Secure` and enables HSTS. **Set this when running behind an ingress**, otherwise all visitors share one rate-limit budget. |
| `SENDORA_DISABLE_IP_BANS` | unset | Explicit `true` switches off the address blocking (see *Blocking repeated failed sign-ins*) regardless of the setting. Recovery switch if an administrator blocked their own address; remove it afterwards. |
| `SENDORA_FORCE_LOCAL_LOGIN` | unset | Explicit `true` re-enables local username/password sign-in at runtime even when an administrator turned it off, without changing the database. Recovery switch for a failing external provider; a warning is logged at startup. Remove it afterwards. |
| `SENDORA_DISABLE_ADMIN_IP_ALLOWLIST` | unset | Explicit `true` switches off the administrator network restriction (`admin_ip_allowlist`, see *Administrator network restriction*) and allows saving a list that does not contain your own address. Recovery switch after locking yourself out; remove it afterwards. |
| `TZ` | environment-dependent | Container timezone; Compose sets UTC. |

SMTP, registration, expiry/cleanup policy, share size limits, object storage, branding, themes, login providers, and email templates are configured through the administrator interface and persisted in SQLite; most of them can also be set by the deployment with `SENDORA_<SETTING>` variables (see *Settings from a ConfigMap or environment variables*).

`APP_URL` takes precedence over the administrator `application_url` setting. For a remote deployment, set one canonical origin such as **`https://files.example.com`** before sending emails or configuring OAuth. Do not rely on request `Host` or forwarded headers to supply the public origin. Token-bearing email links and OAuth callbacks require a configured trusted URL for non-loopback access; HTTP localhost URLs remain allowed for development.

## Flavour

One binary runs as one of three flavours ([CHOOSING-A-FLAVOUR.md](CHOOSING-A-FLAVOUR.md)). Without `SENDORA_FLAVOUR` the mode is detected: `SENDORA_MULTI_TENANT`, then the mode stored by a conversion, then single-tenant.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SENDORA_FLAVOUR` | unset (= 0.2 detection) | `single` (Community single-tenant), `multi` (Community multi-tenant; `SENDORA_MULTI_TENANT=true` is an alias) or `cluster` (PostgreSQL on CloudNativePG, several replicas; **preview**; with `SENDORA_ROLE=web` or `controller`, see the [Cluster quickstart](cluster/QUICKSTART.md)). `single` behaves like `SENDORA_MULTI_TENANT=false`, `multi` like `SENDORA_MULTI_TENANT=true`. |
| `SENDORA_ROLE` | unset | `web` or `controller`; only with `SENDORA_FLAVOUR=cluster`. |

Contradictory settings stop the start: `SENDORA_FLAVOUR=single` with `SENDORA_MULTI_TENANT=true`, `SENDORA_FLAVOUR=multi` with `SENDORA_MULTI_TENANT=false`, `SENDORA_ROLE` without `SENDORA_FLAVOUR=cluster`, or an unknown value. Changing the flavour of existing data is a migration (Admin → Multi-tenant or `sendora-db tenant-import`), never only a changed variable. `GET /api/capabilities` reports the running flavour and which features it offers ([CAPABILITIES.md](CAPABILITIES.md)).

### Cluster flavour configuration (preview)

Cluster requires PostgreSQL on CloudNativePG and separate `web` and `controller` roles. Every replica needs `SENDORA_FLAVOUR=cluster`, its `SENDORA_ROLE`, `SENDORA_BASE_DOMAIN`, `SENDORA_DB_KEY_FILE`, and `SENDORA_PG_POOLER`. The web role connects only through the pooler; only controllers receive direct PostgreSQL access and provisioner credentials. Do not mount provisioner credentials into web pods.

| Variable | Required/default | Purpose and constraints |
|---|---|---|
| `SENDORA_ROLE` | required | `web` or `controller`; only with `SENDORA_FLAVOUR=cluster`. |
| `SENDORA_PG_POOLER` | required | Writable PgBouncer service address as `host:port`, used by both roles. |
| `SENDORA_PG_DIRECT` | controller only | Writable PostgreSQL service address as `host:port`; used by controllers for provisioning, DDL, and coordination. Do not set for web replicas. |
| `SENDORA_PG_SSLMODE` | `verify-full` | TLS mode: `verify-full`, `verify-ca`, or `require`. Prefer the default. |
| `SENDORA_PG_CA_FILE` | required with `verify-full` or `verify-ca` | Path to the CloudNativePG server CA certificate. The file must exist. |
| `SENDORA_PG_PLATFORM_DATABASE` | `sendora_platform` | Platform database name. |
| `SENDORA_PG_PROVISIONER_DIR` | controller only | Directory containing `username` and `password` files for `sendora_provisioner`; required for controllers and forbidden for web replicas. |
| `SENDORA_PG_POOLERS` | `2` (1–16) | Number of PgBouncer instances used for connection-limit calculations. |
| `SENDORA_LEASE_NAME` | `sendora-controller` | Kubernetes Lease name used to elect the controller leader. |
| `SENDORA_POD_NAME` | hostname if unset | Replica identity; set from the Kubernetes downward API in deployments. |
| `SENDORA_COORD_POLL_SECONDS` | `10` (1–300) | Coordinator version-poll interval. |
| `SENDORA_LEASE_SECONDS` | `15` (5–300) | Controller Lease duration in seconds. |
| `SENDORA_BASE_DOMAIN` | required | Base domain for tenant routing; Cluster is always multi-tenant. |
| `SENDORA_DB_KEY_FILE` | controller only | The master key: a 32-byte key file, or a directory of `master-<n>` files for master key rotation, mounted read-only on the controllers. Refused on web replicas, which fetch derived keys from the controllers' key endpoint (`SENDORA_KEY_URL`). See Runtime configuration above. |
| `DATA_DIR` | `./data` | Cluster uses this for files only; it must not contain a Community SQLite database. |

Do not set `SENDORA_DB_INITIALIZE` in Cluster mode; the controller creates and migrates databases. For a deployment overview see the [Cluster quickstart](cluster/QUICKSTART.md).

## Multi-tenant mode

Optional (0.2.0): one process serves many tenants on `<slug>.<base domain>` and a platform console on `admin.<base domain>`. See [MULTI-TENANT.md](MULTI-TENANT.md) for the design; without `SENDORA_MULTI_TENANT=true` none of this applies.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SENDORA_MULTI_TENANT` | unset | `true` enables multi-tenant mode. `DATA_DIR` then holds `platform.db` and `tenants/<id>/`; `SENDORA_DB_KEY_FILE` is the master key from which every database key is derived. |
| `SENDORA_BASE_DOMAIN` | required in multi-tenant mode | Platform host name, optionally with `:port` used only in generated URLs (`sendora.example.com`, `localhost:9090`). URLs are `https` except for `localhost` base domains. |
| `SENDORA_PLATFORM_SETUP_CODE` | generated | Fixed one-time code for creating the first platform administrator. |
| `SENDORA_TENANT_IDLE_MINUTES` | `15` | Close a tenant after this many minutes without requests (1–1440). |
| `SENDORA_MAX_OPEN_TENANTS` | `50` | Maximum tenants open at once; the least recently used idle one is closed first (1–10000). |
| `SENDORA_TENANT_MAINTENANCE_HOURS` | `6` | How often idle tenants are opened for their periodic jobs (1–168). |
| `SENDORA_DEFAULT_MAX_USERS`, `SENDORA_DEFAULT_MAX_STORAGE_BYTES` | `0` | Quotas proposed for new tenants (0 = unlimited). |
| `SENDORA_PLATFORM_AUDIT_RETENTION_DAYS` | `365` | Retention of the platform audit log (90–36500). (`SENDORA_AUDIT_RETENTION_DAYS` keeps setting the tenants' own audit retention.) |
| `SENDORA_PLATFORM_SMTP_HOST`, `_PORT`, `_USER`, `_PASSWORD` / `_PASSWORD_FILE`, `_FROM`, `_TLS` | unset, `587`, …, `starttls` | Default SMTP server for tenants without their own. |
| `SENDORA_RESTART_MODE` | `exec` | How *Restart now* (Admin → Multi-tenant, platform console) restarts after an orderly stop: `exec` replaces the process with the same executable, arguments and environment (no supervisor needed); `exit` exits with code 75 for a supervisor (systemd, Docker restart policy, Kubernetes). |
| `SENDORA_ALLOW_SELF_RESTART` | unset | `true` tells Sendora that a supervisor restarts it after it exits (detected automatically as container PID 1 or in Kubernetes); only affects the hints in the restart screens and the warning logged for `SENDORA_RESTART_MODE=exit`. |
| `SENDORA_NEW_TENANT_STORAGE_OFFER` | `none` | Storage provided to new tenants: `none` (they set up their own), `platform` (the platform bucket with their prefix; needs `SENDORA_PLATFORM_STORAGE_*` or a default storage set in the console) or `local` (the server's disk). Preselected in the create-tenant form. |
| `SENDORA_PLATFORM_MFA_REQUIRED` | `true` | Platform administrators must use an authenticator app. `false` allows password-only sign-in to the console (enrolment stays possible). Changing it in the console needs a fresh confirmation and is audited. |
| `SENDORA_PLATFORM_STORAGE_BACKEND` and the other `SENDORA_PLATFORM_STORAGE_*` | `local` | The platform default object storage: the fields of [Object storage](#object-storage) with `PLATFORM_` in front (for example `SENDORA_PLATFORM_STORAGE_S3_BUCKET`, `SENDORA_PLATFORM_STORAGE_S3_SECRET_KEY_FILE`). Tenants on the default store their files under `<prefix>tenants/<tenant id>/`. `SENDORA_STORAGE_*` is ignored in multi-tenant mode. |

Targets a tenant's administrator configures (SMTP server, OIDC issuer, audit log webhook and syslog, the tenant's own storage endpoint) must not resolve to loopback, private, link-local, CGNAT or metadata addresses in multi-tenant mode; the check runs when saved and on every connection. The platform can allow private targets per tenant in the console. See [MULTI-TENANT.md](MULTI-TENANT.md) §8a.

The offline tool is part of the main binary: `sendora db <command>` or `sendora-db <command>` (a link to the same program in the image). In multi-tenant mode, `sendora-db platform-admin-reset -data-dir <DATA_DIR> -key-file <master key> -user <name> [-mfa] [-password]` (server stopped) removes a platform administrator's authenticator and/or sets a temporary password that must be changed at the next sign-in.

A single-tenant installation can also be converted from **Admin → Multi-tenant** (MULTI-TENANT.md §7.1); the conversion stores the mode in `DATA_DIR/sendora-mode.json`, so `SENDORA_MULTI_TENANT` and `SENDORA_BASE_DOMAIN` are then optional (when set, they win; `SENDORA_MULTI_TENANT=false` keeps or forces single-tenant mode).

In multi-tenant mode `APP_URL` and `JWT_SECRET` are ignored (each tenant's URL comes from its domain and each tenant has its own signing secret). The other `SENDORA_<SETTING>` variables apply to every tenant and are read-only in each tenant's admin screen. All platform settings can also be changed in the platform console unless set by a variable; a changed base domain is stored in the data directory and applies after a restart.

## Settings from a ConfigMap or environment variables

Every setting of **Admin → Settings** can also be set by the deployment, which suits Kubernetes ConfigMaps and GitOps:

- The variable name is `SENDORA_` plus the setting key in capitals, for example `SENDORA_SMTP_HOST` or `SENDORA_ALLOW_SELF_REGISTRATION`.
- **The configuration wins.** At every start the value is validated with exactly the same rules as the admin screen and written to the database. The field is then **read-only** in the admin screen, which lists the managed settings at the top. Change the value in the ConfigMap and restart the pod.
- An invalid value **stops the server** with a message naming the variable, so a typo never silently falls back to a default.
- Removing a variable makes the setting editable in the screen again; it keeps its last value.
- **Secrets** (SMTP password, client secrets) belong in a Kubernetes Secret, not in a ConfigMap. Mount the Secret as files and point to them with the `_FILE` suffix, for example `SENDORA_SMTP_PASSWORD_FILE=/run/secrets/sendora-config/smtp-password`. A plain variable also works. Values from files are used as-is apart from a trailing newline.
- Booleans are `true` or `false`; numbers are whole numbers within the same ranges as in the screen.
- Not configurable this way: the session-signing secret (generated, or `JWT_SECRET`), uploaded logo and favicon, and email template texts (edit them under Admin → Email templates, or import JSON).

| Variable | Default | Admin setting |
|---|---|---|
| `SENDORA_ACCOUNT_PASSWORD_HISTORY` | `5` | `account_password_history` (0 to 24; 0 = no check): a new password must differ from the current one and from this many earlier ones |
| `SENDORA_ACCOUNT_PASSWORD_MAX_AGE_DAYS` | `365` on a new installation, `0` on an upgraded one | `account_password_max_age_days` (0 to 365; 0 = never, less secure): local passwords older than this must be changed (see *Password maximum age and history*) |
| `SENDORA_ACCOUNT_PASSWORD_MIN_LENGTH` | `8` | `account_password_min_length` (8 to 72; a stored value below 8 is raised to 8) |
| `SENDORA_ADMIN_IDLE_LOGOUT_MINUTES` | `15` | `admin_idle_logout_minutes` (0 = same as `idle_logout_minutes`; otherwise administrators get the stricter of the two) |
| `SENDORA_ADMIN_IP_ALLOWLIST` | empty | `admin_ip_allowlist` (IP addresses and CIDR ranges; empty = no restriction) |
| `SENDORA_ADMIN_STEPUP_MINUTES` | `5` | `admin_stepup_minutes` (1 to 60) |
| `SENDORA_ACCOUNT_PASSWORD_REQUIRE_DIGIT` | `false` | `account_password_require_digit` |
| `SENDORA_ACCOUNT_PASSWORD_REQUIRE_LOWER` | `false` | `account_password_require_lower` |
| `SENDORA_ACCOUNT_PASSWORD_REQUIRE_SYMBOL` | `false` | `account_password_require_symbol` |
| `SENDORA_ACCOUNT_PASSWORD_REQUIRE_UPPER` | `false` | `account_password_require_upper` |
| `SENDORA_ALLOW_PREVIEW` | `true` | `allow_preview` |
| `SENDORA_ALLOW_REVERSE_SHARES` | `true` | `allow_reverse_shares` |
| `SENDORA_ALLOW_SELF_REGISTRATION` | `false` | `allow_self_registration` |
| `SENDORA_APPLICATION_NAME` | `Sendora` | `application_name` |
| `SENDORA_APPLICATION_URL` | empty | `application_url` |
| `SENDORA_AUTO_CLEAN_FILES` | `true` | `auto_clean_files` |
| `SENDORA_BACKUP_KEEP` | `7` | `backup_keep` |
| `SENDORA_BACKUPS_ENABLED` | `true` | `backups_enabled` |
| `SENDORA_BACKUP_REMOTE_ENABLED` | `false` | `backup_remote_enabled`: also upload automatic backups to the object store (see *Object storage*) |
| `SENDORA_CLEAN_FILES_DAYS` | `7` | `clean_files_days` |
| `SENDORA_DEFAULT_EXPIRY_TIME` | `7` | `default_expiry_time` |
| `SENDORA_DEFAULT_LANGUAGE` | `en` | `default_language` |
| `SENDORA_DEFAULT_STORAGE_QUOTA_BYTES` | `10000000000` (10 GB) | `default_storage_quota_bytes` |
| `SENDORA_EXPIRY_WARNING_DAYS` | `2` | `expiry_warning_days` |
| `SENDORA_IDLE_LOGOUT_MINUTES` | `60` | `idle_logout_minutes` |
| `SENDORA_PROVIDER_SESSION_MAX_HOURS` | `24` | `provider_session_max_hours` (1 to 720): a session started through a sign-in provider, and every session of an account without a local password, must sign in at the provider again after this many hours, so an account disabled at the identity provider loses access here as well (Admin -> Security -> Sessions) |
| `SENDORA_IP_BAN_ALLOWLIST` | empty | `ip_ban_allowlist` |
| `SENDORA_IP_BAN_ENABLED` | `true` | `ip_ban_enabled` |
| `SENDORA_LOCAL_LOGIN_ENABLED` | `true` | `local_login_enabled` |
| `SENDORA_AUDIT_FORWARD_STDOUT` | `false` | `audit_forward_stdout` (see *Forwarding the audit log*) |
| `SENDORA_AUDIT_FORWARD_SYSLOG` | empty (off) | `audit_forward_syslog` (`host:port`) |
| `SENDORA_AUDIT_FORWARD_SYSLOG_TLS` | `true` | `audit_forward_syslog_tls` |
| `SENDORA_AUDIT_FORWARD_WEBHOOK_URL` | empty (off) | `audit_forward_webhook_url` |
| `SENDORA_AUDIT_LOG_IP` | `false` | `audit_log_ip` (also decides whether the recipient address of a download is stored) |
| `SENDORA_AUDIT_RETENTION_DAYS` | `90` | `audit_retention_days` (90 to 365; a stored value below 90 is raised to 90) |
| `SENDORA_MAX_EXPIRY_TIME` | `30` | `max_expiry_time` |
| `SENDORA_MAX_SHARE_SIZE` | `2048` | `max_share_size` |
| `SENDORA_MFA_POLICY` | `optional` (`off` disables two-step verification entirely; `admins`, `privileged` = administrators and auditors, `all` make it required for local accounts) | `mfa_policy` |
| `SENDORA_MFA_REMINDER_DAYS` | `1` | `mfa_reminder_days` |
| `SENDORA_MFA_TOTP_ENABLED` | `true` | `mfa_totp_enabled` |
| `SENDORA_MFA_WEBAUTHN_ENABLED` | `true` | `mfa_webauthn_enabled` |
| `SENDORA_NOTIFY_NEW_SIGNIN` | `true` | `notify_new_signin` |
| `SENDORA_PASSWORD_BREACH_CHECK_ONLINE` | `false` | `password_breach_check_online` |
| `SENDORA_PRIVACY_URL` | empty | `privacy_url` (https) |
| `SENDORA_REGISTRATION_EMAIL_DOMAINS` | empty | `registration_email_domains` |
| `SENDORA_REQUIRE_EMAIL_VERIFICATION` | `true` | `require_email_verification` |
| `SENDORA_REQUIRE_SHARE_PASSWORD` | `false` | `require_share_password` |
| `SENDORA_SHARE_PASSWORD_MIN_LENGTH` | `8` | `share_password_min_length` |
| `SENDORA_SHARE_PASSWORD_REQUIRE_DIGIT` | `false` | `share_password_require_digit` |
| `SENDORA_SHARE_PASSWORD_REQUIRE_LOWER` | `false` | `share_password_require_lower` |
| `SENDORA_SHARE_PASSWORD_REQUIRE_SYMBOL` | `false` | `share_password_require_symbol` |
| `SENDORA_SHARE_PASSWORD_REQUIRE_UPPER` | `false` | `share_password_require_upper` |
| `SENDORA_SHOW_LANGUAGE_SELECTOR` | `true` | `show_language_selector` |
| `SENDORA_SMTP_FROM` | empty | `smtp_from` |
| `SENDORA_SMTP_HOST` | empty | `smtp_host` |
| `SENDORA_SMTP_PASS` (also `SENDORA_SMTP_PASSWORD`; use `_FILE`) | empty | `smtp_pass` |
| `SENDORA_SMTP_PORT` | `587` | `smtp_port` |
| `SENDORA_SMTP_REPLY_TO` | empty | `smtp_reply_to` |
| `SENDORA_SMTP_TLS` | `starttls` | `smtp_tls` |
| `SENDORA_SMTP_USER` | empty | `smtp_user` |
| `SENDORA_STORAGE_*` | see *Object storage* | `storage_*` |
| `SENDORA_TERMS_ACCEPTANCE_REQUIRED` | `false` | `terms_acceptance_required` (needs `terms_url` and `terms_version`) |
| `SENDORA_TERMS_URL` | empty | `terms_url` (https) |
| `SENDORA_TERMS_VERSION` | empty | `terms_version` |
| `SENDORA_UI_BACKGROUND` | empty | `ui_background` |
| `SENDORA_UI_BUILTIN_BACKGROUND` | `koenigssee` | `ui_builtin_background` |
| `SENDORA_UI_DEFAULT_BACKGROUND` | `true` | `ui_default_background` |
| `SENDORA_UI_SLIDESHOW_SECONDS` | `30` | `ui_slideshow_seconds` |
| `SENDORA_UI_USE_UNSPLASH` | `false` | `ui_use_unsplash` |

### Object storage

Share files are stored in the local data directory unless another backend is selected. All storage settings are under **Admin → Storage** and follow the rules above (variable wins and makes the field read-only; `_FILE` for secrets). The background, credentials, migration and recommended bucket settings are in [STORAGE.md](STORAGE.md).

| Variable | Default | Admin setting |
|---|---|---|
| `SENDORA_STORAGE_BACKEND` | `local` | `storage_backend`: `local`, `s3`, `azure` or `gcs` (where **new** files go; existing files stay where they are until migrated) |
| `SENDORA_STORAGE_S3_ENDPOINT` | empty (AWS S3) | `storage_s3_endpoint`: `https://…`; `http://` only for loopback/private addresses and internal host names |
| `SENDORA_STORAGE_S3_REGION` | `us-east-1` | `storage_s3_region` (required; `auto` for R2) |
| `SENDORA_STORAGE_S3_BUCKET` | empty | `storage_s3_bucket` (S3 bucket naming rules) |
| `SENDORA_STORAGE_S3_PREFIX` | `sendora/` | `storage_s3_prefix` (letters, digits, `.`, `_`, `-`, `/`; normalized to end with `/`) |
| `SENDORA_STORAGE_S3_PATH_STYLE` | `false` | `storage_s3_path_style` (`true` for MinIO and most S3-compatible services) |
| `SENDORA_STORAGE_S3_AUTH` | `static` | `storage_s3_auth`: `static` (access key + secret key) or `default` (AWS default chain: environment, IRSA/web identity, EKS Pod Identity, ECS, instance profile) |
| `SENDORA_STORAGE_S3_ACCESS_KEY` | empty | `storage_s3_access_key` |
| `SENDORA_STORAGE_S3_SECRET_KEY` (use `_FILE`) | empty | `storage_s3_secret_key` (secret, write-only) |
| `SENDORA_STORAGE_AZURE_ACCOUNT` | empty | `storage_azure_account` (3–24 lowercase letters and digits) |
| `SENDORA_STORAGE_AZURE_CONTAINER` | empty | `storage_azure_container` |
| `SENDORA_STORAGE_AZURE_ENDPOINT` | empty (`https://<account>.blob.core.windows.net/`) | `storage_azure_endpoint` (sovereign clouds, Azurite) |
| `SENDORA_STORAGE_AZURE_PREFIX` | `sendora/` | `storage_azure_prefix` |
| `SENDORA_STORAGE_AZURE_AUTH` | `shared_key` | `storage_azure_auth`: `shared_key`, `sas` or `identity` (DefaultAzureCredential: workload identity, managed identity, environment, Azure CLI) |
| `SENDORA_STORAGE_AZURE_ACCOUNT_KEY` (use `_FILE`) | empty | `storage_azure_account_key` (secret, write-only) |
| `SENDORA_STORAGE_AZURE_SAS_TOKEN` (use `_FILE`) | empty | `storage_azure_sas_token` (secret, write-only) |
| `SENDORA_STORAGE_GCS_BUCKET` | empty | `storage_gcs_bucket` |
| `SENDORA_STORAGE_GCS_ENDPOINT` | empty (`https://storage.googleapis.com`) | `storage_gcs_endpoint` (emulators only) |
| `SENDORA_STORAGE_GCS_PREFIX` | `sendora/` | `storage_gcs_prefix` |
| `SENDORA_STORAGE_GCS_AUTH` | `service_account` | `storage_gcs_auth`: `service_account`, `default` (Application Default Credentials, GKE workload identity) or `none` (only with a custom endpoint, for emulators) |
| `SENDORA_STORAGE_GCS_CREDENTIALS_JSON` (use `_FILE`) | empty | `storage_gcs_credentials_json` (secret, write-only) |
| `SENDORA_BACKUP_REMOTE_ENABLED` | `false` | `backup_remote_enabled` (needs a non-local backend; `backup_keep` also applies to the remote copies) |

- Only the settings of the selected backend are used; the others may stay filled in (their stored secrets are kept).
- An incomplete or invalid configuration of the selected backend (for example `s3` without a bucket, `static` without keys) **stops the server** at start. Reachability is not checked at start.
- Saving a changed remote configuration in the screen first runs a **connection test** (write, read and delete a probe object); when it fails nothing is saved. *Test connection* runs the same test with the values in the form without saving them.
- Changing `storage_*` or `backup_remote_*` settings and testing a connection need a **step-up** re-authentication; changes are audited (`settings_changed`, `storage_backend_changed`, `storage_connection_tested` / `storage_connection_test_failed`), secrets by name only.
- When a secret is stored, changing the endpoint, the account or the access key it belongs to requires **entering the secret again** (as for the SMTP password), so stored credentials cannot be redirected to another server.
- Migration of existing files: Admin → Storage → *Migrate files*, or `sendora-db storage-migrate -source <db> -data-dir <dir> -key-file <key> [-dry-run]` (same `SENDORA_STORAGE_*` variables as the server).

### Forwarding the audit log

A copy of the audit log outside the host survives an attacker who controls the server (see the threat model). Admin → Security → Logging, or the variables above, configure up to three destinations at once:

- **Standard output** (`audit_forward_stdout=true`): one JSON line per record, `{"sendora_audit":{...}}`, for the container log collector.
- **Syslog** (`audit_forward_syslog=host:port`): RFC 5424 messages over TCP with octet-counting framing (RFC 6587; RFC 5425 when `audit_forward_syslog_tls=true`, the default, with certificate verification against the system roots). Facility 13 (log audit), severity warning for denied or failed outcomes, informational otherwise; APP-NAME `sendora`, MSGID `audit` or `chain_head`; the message is the same JSON as on standard output.
- **Webhook** (`audit_forward_webhook_url`): HTTPS `POST` of a JSON array of such objects (batches of up to 100), TLS verified, redirects not followed; any 2xx answer counts as delivered. Plain `http://` is accepted for `localhost` only. A bearer token is read from the file named by `SENDORA_AUDIT_FORWARD_WEBHOOK_TOKEN_FILE` (same permission rule as every other `*_FILE` secret); never put credentials in the URL, which is visible in the settings and in the audit log.

Every record is forwarded with all its fields including `seq`, `prev_hash` and `hash`, so the receiver can verify the chain and detect gaps. Every five minutes, at start and at an orderly stop, a heartbeat `{"sendora_audit_chain_head":{"last_seq":…,"hash":"…","ts":"…","reason":"start|periodic|stop"}}` carries the current end of the chain; it is not part of the chain. A head that moves backwards, or records missing below it, means the local log was changed or truncated.

Forwarding never blocks or fails a request: each destination has an in-memory queue of 10,000 records, failed deliveries are retried with exponential backoff (1 second up to 5 minutes), and a full queue drops records and counts them. Delivery is at least once (a retried batch may arrive twice; deduplicate on `seq`). `GET /api/audit/status` and `GET /api/logs/status` report per destination `enabled`, `last_success`, `last_error` (an error class such as `connect`, `tls`, `timeout`, `http_status_503` or `token_file`, never an address or secret), `last_error_at`, `queued`, `dropped`, `failed` and `delivered`. Destinations on link-local addresses (including cloud metadata services) are refused, both when saved and after DNS resolution; private (RFC 1918) and loopback addresses are allowed (in multi-tenant mode a tenant's destinations are also refused on those, see *Multi-tenant mode*). When a destination is removed or changed, the record of that settings change is still delivered to the old destination.

### Readiness and metrics

- `GET /api/health` is the liveness probe: the process answers HTTP.
- `GET /api/health/ready` (no authentication) answers `200` or `503` with `{"status":"ok|fail","checks":{...}}`. Checks: `database` (a query), `audit_log` (the last audit write succeeded and the database is writable; no record is written), `disk` (at least 256 MiB free in `DATA_DIR`), `backup` (only while `backups_enabled`: the newest backup is at most 48 hours old, i.e. two automatic backup intervals; tolerated during the first hour after a start) and `audit_chain` (the incremental chain verification; while the start-up verification of a large log is still running the last known result is used). Use it as the Kubernetes readiness probe.
- `GET /api/metrics` serves Prometheus text format and is **off (404)** unless `SENDORA_METRICS_TOKEN_FILE` names a file holding a token (same permission rule as the other `*_FILE` secrets). Scrapers send it as `Authorization: Bearer <token>`. Counters: `sendora_logins_total{result="ok|failed"}`, `sendora_mfa_failures_total`, `sendora_audit_write_failures_total`, `sendora_audit_forward_dropped_total{sink}`, `sendora_audit_forward_failed_total{sink}`, `sendora_decrypt_failures_total`, `sendora_ip_bans_total`, `sendora_downloads_started_total`, `sendora_uploads_completed_total`. Gauges: `sendora_upload_sessions_active`, `sendora_verified_download_slots_in_use`, `sendora_audit_forward_queue_length{sink}`. Counters restart at zero with the process.

| Variable | Purpose |
|---|---|
| `SENDORA_AUDIT_FORWARD_WEBHOOK_TOKEN_FILE` | File with the bearer token for the audit webhook (optional). |
| `SENDORA_METRICS_TOKEN_FILE` | File with the bearer token for `/api/metrics`; without it the endpoint is off. |
### Account security

- **Password screening.** Account passwords (setup, registration, profile, reset, administrator-created users) are refused when they are on the embedded list of common passwords (`internal/app/data`, reproducible with `gen_common_passwords.go`), contain the username, the local part of the email address or the application name, or are a simple repetition or sequence. Share passwords keep their own rules. With `password_breach_check_online=true` new passwords are also checked against the Have I Been Pwned range API: only the first 5 hex characters of the SHA-1 hash are sent (k-anonymity), with a 3-second timeout; when the service cannot be reached the password is accepted and a warning is logged.
- **Password maximum age and history.** `account_password_max_age_days` (Admin → Security → Account password policy, 0 to 365, 0 = never) makes a local password expire that many days after it was set. **A new installation starts at 365; an installation that already had accounts when it was upgraded starts at 0**, so nobody is forced to change at the upgrade (existing passwords count as set at the upgrade). 0 is less secure; modern guidance (NIST SP 800-63B) prefers password screening and two-step verification over frequent rotation. It applies only to accounts with a local password: not to guests, not to accounts that sign in only through a provider, and not to users an administrator marked *Exempt from password rotation* under Users. An expired password must be changed before anything else (the forced-change flow on the profile page): at the next sign-in, or, for a session that is already running, at its next request, which ends the account's sessions so the user signs in again with the old password and then chooses a new one. Users see a banner from 14 days before expiry and get one reminder email (template `password_expiry_warning`) 7 days before, when their address is verified, SMTP and a public URL are configured. `account_password_history` (0 to 24, default 5, 0 = no check) refuses a new password equal to the current one or one of the last N; earlier passwords are stored only as bcrypt hashes and the oldest are removed at each change. Each remembered password costs one bcrypt comparison (about 250 ms) when a password is changed. The access review shows `password_age_days`, `password_rotation_exempt` and `password_expires_at`.
- **Security notifications.** Users with a verified email address get an email when their password is changed (also through a reset link), a second factor is added or removed, or recovery codes are regenerated, and (setting `notify_new_signin`) when a sign-in comes from a browser family and network (/16 for IPv4, /48 for IPv6) not seen for the account in the last 30 days. Only keyed hashes of that combination are stored, never addresses. A failing mail server never blocks the action.
- **Step-up re-authentication.** Deleting or erasing users, changing administrator/auditor roles, creating, changing or deleting sign-in providers, changing security settings (`mfa_*`, `local_login_enabled`, `application_url`, `audit_*`, `ip_ban_*`, the account password policy, `admin_*`, `provider_session_max_hours`, `password_breach_check_online`, `notify_new_signin`), changing storage settings (`storage_*`, `backup_remote_*`), testing a storage connection, starting or cancelling a storage migration, downloading, deleting and restoring backups, and MFA reset requests need a sign-in or confirmation not older than `admin_stepup_minutes`. The browser asks for the second factor (authenticator code or passkey) or, without one, the password. Administrators who sign in only through a provider and have no second factor sign in at the provider again. Administrator sessions also end after `admin_idle_logout_minutes` of inactivity.

### Administrator network restriction

`admin_ip_allowlist` limits the administration routes and the audit log to client addresses in the list (one IP address or CIDR range per line; empty means no restriction). The client address is determined as everywhere else: forwarded headers count only from `SENDORA_TRUSTED_PROXIES`. Refused requests get `403` and an `access_denied` audit record. Saving a list that does not contain your own current address is refused. If you lock yourself out (for example after the office address changed), restart with `SENDORA_DISABLE_ADMIN_IP_ALLOWLIST=true`, fix the list and remove the variable again.

### Privacy and terms

`privacy_url` and `terms_url` (https) are shown in the footer, on the sign-in page and on public share pages. With `terms_acceptance_required=true` (and a `terms_version`) every signed-in account accepts the current version once (`terms_accepted` in the audit log); until then only its profile, the acceptance, the personal data export and deleting the account work. Changing `terms_version` asks everyone again. Users can download their data (Profile → Your data) and delete their account; administrators can erase an account under Users (see `docs/THREAT-MODEL.md` for what remains in the audit log).

### Login providers

Login providers can be configured the same way, with `SENDORA_PROVIDER_<ID>_<FIELD>`. `<ID>` consists of capital letters and digits and keeps the provider's callback URL stable: `<APP_URL>/api/auth/oidc/config-<id>/callback` (in lower case), which you register at the identity provider.

| Field | Meaning |
|---|---|
| `TYPE` | `entra`, `oidc`, `google` or `github` (required) |
| `NAME` | Name on the sign-in button (default: the ID) |
| `TENANT_ID` | Entra directory (tenant) ID |
| `ISSUER_URL` | Issuer URL for `oidc` |
| `CLIENT_ID` | Application (client) ID (required) |
| `CLIENT_SECRET` / `CLIENT_SECRET_FILE` | Client secret value; prefer the `_FILE` form from a Secret |
| `ENABLED` | `true` (default) or `false` |
| `ALLOW_REGISTRATION` | Create accounts at first sign-in: `false` (default) or `true` |
| `TRUST_EMAIL` | Trust the provider's verified email (`false` by default; never used for Entra) |
| `ICON` | Optional icon name |

Example for Microsoft Entra ID:

```sh
SENDORA_PROVIDER_ENTRA_TYPE=entra
SENDORA_PROVIDER_ENTRA_NAME="Company login"
SENDORA_PROVIDER_ENTRA_TENANT_ID=00000000-0000-0000-0000-000000000000
SENDORA_PROVIDER_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000000
SENDORA_PROVIDER_ENTRA_CLIENT_SECRET_FILE=/run/secrets/sendora-config/entra-client-secret
SENDORA_PROVIDER_ENTRA_ALLOW_REGISTRATION=true
# callback URL to register in Entra: <APP_URL>/api/auth/oidc/config-entra/callback
```

Configured providers are marked *Managed by configuration* under Admin → Login providers and cannot be edited or deleted there. The type, client ID or issuer of a provider that already has linked accounts cannot change (the server refuses to start); use a new `<ID>` instead. Unknown `SENDORA_PROVIDER_*` variables stop the server, so typos are caught. Removing all variables of a provider makes it editable again.
