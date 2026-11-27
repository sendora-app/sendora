# Security whitepaper

This document gives an auditor or security reviewer one place to read how Sendora is built and secured: architecture, trust boundaries, authentication, authorisation, cryptography, logging, data protection, secure development and known limitations. It summarises what the code does and links to the detailed documents rather than repeating them. Every statement was checked against the source code of the version below; where something an auditor might expect is not there, this document says so.

Written for version 0.2.0. The Cluster flavour of 0.3 is not covered yet ([cluster/QUICKSTART.md](../cluster/QUICKSTART.md), [ENCRYPTION.md](../ENCRYPTION.md)). Object storage and multi-tenant mode are optional; with the defaults (local data directory, single-tenant) Sendora behaves as 0.1.5.

[Back to the compliance index](README.md)

> **Status.** Sendora is a volunteer, open-source project written largely by an AI coding assistant. It has automated tests and has had code reviews, but it has **not** been independently audited or penetration tested (see [SECURITY.md](../../SECURITY.md)).

## 1. Architecture

| Component | Technology | Notes |
|---|---|---|
| Server | One Go executable (`main.go`, `internal/app`, `internal/store`, `internal/filecrypt`) with the chi router | Serves the API under `/api` and the embedded single-page app. Plain HTTP only; TLS is terminated in front (reverse proxy or Ingress) |
| Web interface | Vue 3 (`web/src`), built into the executable | No inline script; CSP `script-src 'self'` |
| Database | SQLite with SQLCipher 4.20.0 (built from a checksum-verified source in the `Dockerfile`), file `DATA_DIR/sendora.db` | Accounts, shares metadata, settings, secrets, audit log |
| Share file storage | `DATA_DIR/shares/<link id>/<index>_<file name>` (default `local` backend), or an S3-compatible, Azure Blob or Google Cloud Storage bucket as `<prefix>files/<32 random hex>` (`internal/storage`) | File contents AES-256-GCM per file (format in [FILE-FORMAT.md](../FILE-FORMAT.md)), encrypted **before** upload to an object store; local directory and file names are not encrypted, object names are random. See [STORAGE.md](../STORAGE.md) |
| Upload staging | `DATA_DIR/uploads/<session>/` | Parts in plain form while an upload is in progress; removed on completion, abort or after 24 h |
| Download snapshots | `DATA_DIR/.verified-download-*` | Temporary plain copies for verified downloads; removed after the transfer and at start |
| Backups | `DATA_DIR/backups/`, optionally copied to `<prefix>backups/` in the object store (`backup_remote_enabled`) | SQLCipher-encrypted copies of the database (not the share files) |
| Multi-tenant mode (optional) | `SENDORA_MULTI_TENANT=true`: `internal/platform`, `internal/app/mt_*.go`; `DATA_DIR/platform.db` plus `DATA_DIR/tenants/<random id>/` per tenant | One process routes by host to one server instance per tenant, each with its own SQLCipher database and keys; a platform console on `admin.<base domain>`. See [MULTI-TENANT.md](../MULTI-TENANT.md) |
| Command-line tool | `sendora-db` = `sendora db` (`internal/dbcli`, part of the `sendora` binary) | Key generation, backup, verification (`verify`, `verify-files`, `audit-verify`), offline MFA reset, `storage-migrate`, `tenant-import`, `platform-admin-reset` |
| Container image | `Dockerfile`: Debian 13 slim, user 10001, no setuid/setgid binaries | Example manifests in `deploy/` (read-only root file system, all capabilities dropped, `no-new-privileges`, recommended NetworkPolicies in `deploy/networkpolicy*.yaml` and `docs/cluster/examples/`, applied separately because they depend on the CNI) |

Sendora is a **single-instance** application: one process owns the data directory (in multi-tenant mode one process serves all tenants). There is no clustering or built-in high availability.

The data flows are described in [DATA-FLOW.md](DATA-FLOW.md).

## 2. Trust boundaries

| Boundary | Assumption / control |
|---|---|
| Internet → reverse proxy | Operator terminates TLS. Sendora sets HSTS (180 days) only when the request arrived over HTTPS as seen through a trusted proxy |
| Reverse proxy → Sendora | `SENDORA_TRUSTED_PROXIES` lists the proxies whose `X-Forwarded-For`/`X-Forwarded-Proto` are believed; otherwise the TCP peer is the client |
| Browser ↔ server | The browser runs the shipped JavaScript. CSP, `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Sec-Fetch-Site`/`Origin` checks against CSRF |
| Sendora process ↔ data volume | The process holds the database key in memory. Anyone who controls the running process or the key file can read everything. **Sendora is not end-to-end encrypted** |
| Sendora → outbound services | SMTP, identity providers, audit forwarding, optional Have I Been Pwned. Outbound OIDC and forwarding requests refuse loopback (OIDC), link-local and cloud-metadata addresses after DNS resolution |
| Sendora → object storage (optional) | The provider receives ciphertext only under random names; it sees sizes, times and access patterns, and can delete or withhold objects (availability), not read or undetectably change them. Credentials are stored in the encrypted database; redirecting a stored secret to another endpoint requires re-entering it |
| Tenant ↔ tenant (multi-tenant) | Separate database, directory, derived keys, signing secrets and HMAC keys per tenant; host-only cookies; routing only by host (`X-Forwarded-Host` only from trusted proxies). Targets a tenant administrator configures (SMTP, OIDC, audit forwarding, own storage endpoint) must not resolve to loopback, private, link-local, CGNAT or metadata addresses (`internal/netguard`, checked when saved and on every connection) |
| Platform console ↔ tenants | Platform administrators manage tenants, quotas, domains and storage offers but see counts only, never tenant users, shares, files, audit details or a tenant's own storage configuration. TOTP is required by default (`platform_mfa_required`) |

The full actor and threat analysis is in [THREAT-MODEL.md](../THREAT-MODEL.md).

## 3. Authentication

### 3.1 Local accounts

- Passwords are hashed with bcrypt, cost 12; older hashes are upgraded after a successful sign-in.
- Policy: minimum length 8 (configurable 8–72), optional character classes. New passwords are screened against an embedded list of common passwords, the username, the local part of the email address, the application name and trivial repetitions or sequences. Optionally (`password_breach_check_online`, default off) the Have I Been Pwned range API is queried with the first 5 hex characters of the SHA-1 hash (k-anonymity, `Add-Padding`, 3-second timeout; unreachable service = accepted with a log warning).
- Maximum password age: `account_password_max_age_days` (0–365, 0 = off; **365 for new installations, 0 for installations upgraded with existing accounts**, so an upgrade never forces a change). It applies to accounts with a local password, not to guests, provider-only accounts or accounts an administrator exempted (`password_rotation_exempt`, audited). An expired password sets the forced-change flag at the next sign-in, or in the authentication middleware within one access-token lifetime for a running session; in that case the sessions are ended and the user signs in again, because a session token alone must not choose a new password without the current one. Users see a banner from 14 days before expiry and get one reminder email 7 days before (verified address, SMTP configured). Modern guidance (NIST SP 800-63B) prefers screening and MFA over periodic rotation; the setting exists for policies that require it.
- Password history: `account_password_history` (0–24, default 5, 0 = off). A new password equal to the current one or one of the last N is refused (reset link, profile, administrator's own change). Earlier passwords are kept only as bcrypt hashes (`password_history`, newest N per account, deleted on erasure).
- Self-registration is off by default; with it on, email verification (default on) and an optional domain allowlist apply. Unverified registrations are removed after 48 hours.

### 3.2 Multi-factor authentication

- Factors: TOTP authenticator apps with one-time recovery codes (stored hashed), and WebAuthn passkeys/security keys. WebAuthn verification is an in-house implementation (`internal/webauthnlite`); attestation is not evaluated (attestation "none").
- Global policy `mfa_policy`: `off`, `optional` (default for new installations), `admins` (required for administrators), `privileged` (required for administrators and auditors) or `all`; per-user override. A corrupt stored value fails closed to `all`. Required policies apply to accounts with a local password; accounts that sign in only through an identity provider rely on the provider's MFA.
- Administrators reset another user's MFA only through a 24-hour, single-use confirmation link sent to the user's verified address; the user is notified afterwards.

### 3.3 External identity providers

- OpenID Connect (generic), Google, GitHub and Microsoft Entra ID. Entra requires an explicit organisation tenant GUID (multi-tenant and consumer authorities are refused).
- Authorisation code flow with `state`, `nonce` and PKCE. Discovery and token requests time out after 5 seconds, follow at most 3 redirects, ignore `HTTP(S)_PROXY` and refuse loopback, link-local and metadata addresses.
- Account creation at first provider sign-in is off unless enabled per provider; trusting the provider's email is off by default and never used for Entra.
- Local sign-in can be switched off (`local_login_enabled`) with lock-out protection for the last external administrator and a recovery variable (`SENDORA_FORCE_LOCAL_LOGIN`).

### 3.4 Brute-force protection

| Control | Behaviour |
|---|---|
| Per-account lockout | 5 consecutive failures (password, second step, step-up and wrong current password share one counter) lock password sign-in for 15 minutes; administrators can unlock |
| IP ban | 10 failed credential checks from one address (IPv6 grouped per /64) within 10 minutes ban it from sign-in style routes for 30 minutes, doubling per repeat up to 24 hours; stored in the database; administrators can lift bans; allowlist and on/off setting |
| Rate limits | Per-address budgets per route class and minute (for example login 60, MFA 30, share unlock 60, downloads 120, refresh/logout 240); setup limited across all addresses |
| Share passwords | bcrypt; a client is blocked after 10 wrong passwords in 10 minutes, the whole share after 50 |

### 3.5 Sessions

| Property | Value |
|---|---|
| Access token | JWT HS256, 15 minutes, `purpose` and credential-version claims, session ID claim; signing keys derived per purpose with HKDF-SHA256 from the stored secret |
| Refresh token | Random, stored hashed; `HttpOnly`, `SameSite=Lax`, path `/api/auth`, `Secure` behind HTTPS; rotated on every use; reuse of a spent token signs out all sessions of the account (`session_reuse_detected`) |
| Absolute lifetime | 30 days, not extended by rotation |
| Idle timeout | `idle_logout_minutes` (default 60); administrators `admin_idle_logout_minutes` (default 15, stricter value wins) |
| Provider session limit | `provider_session_max_hours` (default 24, 1–720): provider-started sessions, and all sessions of accounts without a local password, must sign in at the provider again, so an account disabled at the IdP loses access |
| Session management | Users list and end their own sessions; administrators sign a user out everywhere; revoking a session also invalidates its access tokens immediately |
| Credential change | A change of password, email address, forced-change flag or second factors invalidates existing access tokens (credential-version claim); a forced reset, an account update that changes credentials and an account disable also delete the refresh tokens |

### 3.6 Step-up re-authentication and administrator network restriction

- Critical administrator actions need a sign-in or confirmation not older than `admin_stepup_minutes` (default 5, 1–60): deleting or erasing users, changing administrator/auditor roles, creating/changing/deleting sign-in providers, changing security settings, changing storage settings, testing a storage connection, starting or cancelling a storage migration, scheduling the multi-tenant conversion and *Restart now*, downloading, deleting and restoring (importing) backups, and MFA reset requests. Confirmation is by second factor, or password when no factor exists; provider-only administrators sign in at the provider again. Applying an import additionally requires the administrator's local password.
- `admin_ip_allowlist` (empty by default) restricts administration routes and the audit log to listed addresses or CIDR ranges; refusals are audited (`access_denied`). Saving a list that excludes the caller is refused; `SENDORA_DISABLE_ADMIN_IP_ALLOWLIST=true` is the recovery switch.

## 4. Authorisation model

| Role | Can | Cannot |
|---|---|---|
| `user` | Upload, manage **own** shares and invitations, see own download history, manage own profile, factors and sessions, export or erase own data | Anything administrative; other users' shares |
| `admin` | Manage users, roles, settings, providers, branding, backups, imports; read the audit log and the access-review report | **Read, list, open or manage other users' shares or download history** (owner-only checks with `user_id` in every share query; foreign shares answer 404 and are audited as `access_denied`). Statistics contain counts only. Set another user's password (reset link only) |
| `auditor` | Read the audit log, its chain status and exports; read and export the access-review report; own profile, factors, sessions, data export, terms, erasure | Anything else (allowlist `auditorAllowed`); upload or share. Administrator and auditor are mutually exclusive |
| `guest` | Upload into the one reverse-share invitation it was created for, while that invitation is valid | Everything else ("upload-only") |
| Recipient (no account) | Download and preview a share with its link (and password, if set), within expiry and download limit | — |

Every route's intended policy is declared in a route access matrix (`internal/app/route_access_test.go`); the test fails if a route lacks a declared policy and calls every route as every principal.

Administrator residual powers (documented in the threat model): delete a user and thereby their shares, change settings, import a database, and see user names and email addresses. There is **no four-eyes (dual control) approval** for any action.

## 5. Cryptography

| Use | Mechanism |
|---|---|
| Database at rest | SQLCipher 4.20.0 (AES-256-CBC with HMAC-SHA512 per page), raw 32-byte key from `SENDORA_DB_KEY_FILE` |
| Multi-tenant keys | The key file is the master key and is never used directly: `HKDF-SHA256(master, "sendora/v1/platform-db")` for the platform database, `HKDF-SHA256(master, "sendora/v1/tenant-db/<tenant id>")` (128-bit random ID) per tenant; file, audit, token and HMAC keys follow from the tenant key. Tenants imported from a single-tenant installation keep the old key as the root of their file and audit keys (*legacy root*) |
| Share files at rest | AES-256-GCM in 64 KiB chunks, per-file key via HKDF-SHA256 from the database key and a random 32-byte salt; format v2 binds a random file ID into every chunk's AAD; last-chunk flag prevents truncation/extension. Specification and test vectors: [FILE-FORMAT.md](../FILE-FORMAT.md) |
| Integrity of downloads | SHA-256 recorded at upload and checked for verified downloads; modified chunks answer 409 and are audited |
| Audit chain | HMAC-SHA256 chain with an HKDF-derived key; checkpoints on retention purge |
| Passwords | bcrypt cost 12 (account and share passwords) |
| Tokens | HS256 with per-purpose HKDF subkeys; refresh, reset and MFA-reset tokens stored as hashes |
| Backups | Same SQLCipher key as the live database (remote copies are the same encrypted file) |
| In transit | Not provided by Sendora itself (plain HTTP listener). Outbound: SMTP with STARTTLS (default) or implicit TLS, minimum TLS 1.2, mode `none` possible; syslog over TLS by default; webhook HTTPS only (HTTP only for `localhost`); object storage over HTTPS (`http://` only for loopback, private and cluster-internal hosts) |

**Key handling.** The key file must be a regular file of exactly 32 bytes, owned by root or the service user, without group-write or world access; Sendora refuses to start otherwise. The key is never logged, never placed in a connection string, and buffers holding it are wiped after use. Only a fingerprint (first 8 bytes of an HMAC) is logged and audited (`key_fingerprint_changed`). On Linux core dumps are disabled and the process is made non-dumpable. Other secrets (`JWT_SECRET_FILE`, SMTP password, provider client secrets, webhook and metrics tokens) follow the same file-permission rule.

**Limits.** No key rotation once encrypted files exist; the root key is used both by SQLCipher and as input to file-key derivation (no formal key separation); no HSM/KMS integration (key custody is the operator's responsibility); files uploaded before 0.1.2, upload parts and download snapshots are plain on disk; on the volume, each share directory is named after the share's **link ID** (`DATA_DIR/shares/<link id>/`) and each stored file is named `<index>_<original file name>`, so someone with a copy of the volume (without the key) learns link IDs, file names, sizes, counts and times, and could use a link ID to download a share that has no password while it is still active on the live server; whole-database rollback is not detected.

## 6. Logging and monitoring

- **Tamper-evident audit log**, always on, written synchronously (one retry; failure reported on stderr and counted). Critical administrator actions write an `attempted` record first and are refused with 503 if it cannot be stored. A middleware records all other mutating requests and denied access by signed-in users. Full catalogue: [AUDIT-EVENTS.md](AUDIT-EVENTS.md).
- **Verification:** incremental chain verification behind `GET /api/audit/status` and the readiness check; full verification in the background at start; offline with `sendora-db audit-verify` (non-zero exit on a break). Triggers count updates/deletes into `audit_guard` so modifications force a re-check.
- **Retention:** `audit_retention_days`, 90 to 365 days (default 90). Lower values are refused; a purge whose records do not verify is refused. Changes to retention and to IP logging are themselves audited.
- **Privacy:** client IP addresses are stored only with `audit_log_ip` (default off). Shares appear as `share#N`; no names, link IDs, file names, passwords, tokens or secret values.
- **Access:** administrators and auditors read the same log; every page view (rate-limited), every export and every backup download is recorded, exports before they are served.
- **Forwarding** to standard output (JSON lines), syslog (RFC 5424 over TCP, TLS by default) and/or an HTTPS webhook (bearer token from a file), with per-destination queues (10,000 records), retries with backoff, at-least-once delivery, and a `chain_head` heartbeat every 5 minutes, at start and at stop. Status per destination via `/api/audit/status`. Details: [configuration.md](../configuration.md#forwarding-the-audit-log).
- **Readiness and metrics:** `GET /api/health` (liveness), `GET /api/health/ready` (database, audit write state, ≥256 MiB disk, backup age ≤48 h when backups are on, audit chain), `GET /api/metrics` (Prometheus, off unless a token file is configured). See [configuration.md](../configuration.md#readiness-and-metrics).
- **Security notifications** by email to users for password changes, factor changes, recovery-code regeneration, MFA reset, email change (to the old address) and sign-ins from a new browser family and network, plus a reminder 7 days before a password reaches its maximum age.
- **Not provided:** alerting, correlation or a SIEM. Sendora produces the data; detection and response are the operator's process. No HTTP access log is written by Sendora.

## 7. Data protection

- Encryption at rest for the database, backups and share files (section 5). Volume or disk encryption for the remaining plain data is the operator's responsibility.
- IP minimisation: audit IPs, session IPs and download recipient IPs are stored only while `audit_log_ip` is on; switching it off empties stored download addresses at the next maintenance run. New-sign-in detection stores only keyed hashes of (browser family, /16 or /48 network).
- Automatic retention: expired shares and their files are removed after `clean_files_days` (default 7); download history after 90 days; sessions after 30 days at most; audit records after the retention period. See [PERSONAL-DATA.md](PERSONAL-DATA.md).
- GDPR support: self-service export of the user's own data (JSON, recorded as `personal_data_exported`), self-service account erasure, administrator erasure (step-up), rectification through the profile. Erasure deletes content and pseudonymises the account row; audit records keep the former username until retention removes them (legitimate interest, documented in the threat model).
- Optional privacy and terms links, and a terms-acceptance requirement with versioning (`terms_accepted` audit event).
- The share link is the access credential for recipients: forwarded links work for anyone. Expiry, download limits and passwords are the controls.

## 8. Secure development and supply chain

| Practice | Implementation |
|---|---|
| Tests | Go unit and integration tests (run with `-race` in CI) and Node tests for the web interface; a route access matrix test over every route and principal; a test that every mutating route is audited or explicitly exempt; tamper tests for the audit chain and the file format |
| Fuzz and property tests | `FuzzReader` and property tests for the encrypted-file reader (`internal/filecrypt`), `FuzzDecode` for the WebAuthn CBOR decoder; test vectors checked by an independent Python script (`docs/tools/verify_vectors.py`) |
| Static analysis | CodeQL for Go and JavaScript/TypeScript on every push to `main`, every pull request and weekly |
| Dependency vulnerability scanning | `govulncheck` (reachable code, Go modules and standard library) and `npm audit --omit=dev --audit-level=high` fail the CI build |
| Image scanning | Trivy scans the latest published image weekly; all findings go to code scanning; the run fails on fixable HIGH/CRITICAL findings |
| Dependency updates | Dependabot weekly for Go modules, npm, Docker base images and GitHub Actions (minor/patch grouped) |
| Pinning | GitHub Actions pinned to commit SHAs; base images pinned by digest; Go modules by `go.sum`; SQLCipher source by SHA-256. Debian packages in the image are **not** version-pinned |
| Release gating | The release workflow runs the full CI for exactly the tag before building; a published version is never rebuilt |
| Builds | Native builds per platform (amd64 and arm64 runners), merged into one multi-arch manifest |
| Provenance, SBOM, signature | GitHub build-provenance attestation, SPDX SBOM attestation, keyless cosign signature bound to the release workflow and tag |

The provenance, SBOM and signature apply to images built by the new release workflow, i.e. **from 0.1.5 onwards**. Images up to and including 0.1.4 are unsigned and have no attestations. Verification commands are in [SECURITY.md](../../SECURITY.md#verifying-release-images) and [VULNERABILITY-AND-DEPENDENCY-MANAGEMENT.md](VULNERABILITY-AND-DEPENDENCY-MANAGEMENT.md).

Not in place: mandatory independent code review (single maintainer), DAST, penetration testing, reproducible-build verification, signed commits requirement.

## 9. Vulnerability handling

Reports go through GitHub private vulnerability reporting. Response goals (not guarantees): acknowledgement within 5 working days, first assessment within 14 days, a fix or documented mitigation for critical issues within 30 days. Only the latest release receives fixes. See [SECURITY.md](../../SECURITY.md) and [VULNERABILITY-AND-DEPENDENCY-MANAGEMENT.md](VULNERABILITY-AND-DEPENDENCY-MANAGEMENT.md).

## 10. Known limitations

- Not end-to-end encrypted; the host operator and anyone with the key or process memory can read all data.
- No malware or content scanning of uploads; no data-loss prevention.
- No four-eyes approval; no legal hold or e-discovery; no records-management holds on shares.
- Single instance; no built-in high availability. Backups contain the database only; an off-site copy exists only with an object store and `backup_remote_enabled`.
- No native TLS; no `/.well-known/security.txt` (see [README.md](README.md#securitytxt)).
- No key rotation once encrypted files exist; no HSM/KMS.
- Whole-database rollback is not detected; the audit chain proves integrity of what is present, and forwarding plus the heartbeat is the defence against truncation.
- Account lockout can be triggered by anyone who knows a username (15 minutes).
- Invite tokens are stored in plain text in the (encrypted) database.
- Plain upload parts and download snapshots exist on disk during transfers.
- Share directory names on the volume are the link IDs, and stored file names contain the original file names (section 5): protect volume copies and volume backups as sensitive.
- Verified-download slots are global and limited.
- Most offline `sendora-db` actions (for example `mfa-reset`, `backup`, `verify`) are not audited; `storage-migrate`, `tenant-import` and `platform-admin-reset` write audit records.
- Passkeys are tested against a software authenticator and test vectors, not every real device.
- Multi-tenant mode isolates tenants from each other and from the console, not from the host operator, who holds the master key. With `platform_mfa_required=false` a stolen console password controls every tenant.
- An object storage provider sees object sizes (approximate file sizes) and access times, and keeps deleted objects as long as its versioning or soft delete retains them.
- Not independently audited or penetration tested.

More detail: [THREAT-MODEL.md](../THREAT-MODEL.md) sections 4a, 5 and 6, and the wiki pages [Security notes](https://github.com/sendora-app/sendora/wiki/Security-Notes), [Encryption](https://github.com/sendora-app/sendora/wiki/Encryption) and [Hardening guide](https://github.com/sendora-app/sendora/wiki/Hardening-Guide).
