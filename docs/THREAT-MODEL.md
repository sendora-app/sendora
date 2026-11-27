# Threat model

What Sendora protects, against whom, what it does not protect, and where the checks are. It is the starting point for a security audit; the file format is specified separately in [FILE-FORMAT.md](FILE-FORMAT.md).

Status: applies to 0.3.0, all three flavours (single-tenant, multi-tenant and the Cluster preview; [CHOOSING-A-FLAVOUR.md](CHOOSING-A-FLAVOUR.md)), written from the code and from code reviews. Encryption and keys are detailed in [ENCRYPTION.md](ENCRYPTION.md), object storage in [STORAGE.md](STORAGE.md), multi-tenancy in [MULTI-TENANT.md](MULTI-TENANT.md). Sendora has not been audited by an independent party.

## 1. Assets

| Asset | Where it lives | Protected by |
|---|---|---|
| Shared file contents | `DATA_DIR/shares/<link id>/` (in the Cluster flavour on a volume shared by the replicas), or an object store under `<prefix>files/<random>` | AES-256-GCM per file under the tenant's `files` key; volume encryption for files uploaded before 0.1.2 |
| Share metadata, accounts, settings, secrets, audit log | SQLite flavours: `DATA_DIR/sendora.db` (per tenant `DATA_DIR/tenants/<id>/sendora.db`). Cluster: one PostgreSQL database per tenant | SQLite flavours: SQLCipher (AES-256-CBC + HMAC-SHA512 per page). Every flavour: column encryption (AES-256-GCM, bound to table, column and row) of names, e-mail addresses, password hashes, share and file names, settings, secrets and audit text. The Cluster flavour has no whole-database encryption |
| The root key (master key) | the file named by `SENDORA_DB_KEY_FILE`; in the Cluster flavour a file or a directory of `master-<n>` versions, on the controllers only | file mode/owner checks, never logged, never in a connection string |
| Per-tenant data keys and control log | each tenant's database, wrapped under the tenant's KEK | AES-256-GCM wrapping; an authenticated control log of every key event, verified when the database is opened |
| A tenant-managed KEK (Cluster) | held by the tenant; in controller memory while unlocked | never stored by the platform (only its fingerprint) |
| Share link IDs (about 86 bits) | database, URLs given to recipients, and the names of the share folders in `DATA_DIR/shares/` | `crypto/rand`, unguessable; optional share password; the folder names are visible to anyone with a copy of the volume (see 5.1) |
| Account credentials, sessions, MFA factors | database | bcrypt, hashed refresh/reset tokens, TOTP/WebAuthn |
| Backups | SQLite flavours: `DATA_DIR/backups/`; optionally a copy in the object store (`<prefix>backups/`). Cluster: the operator's PostgreSQL backups | same SQLCipher key and column encryption; in PostgreSQL backups only the column encryption |
| Object storage credentials | settings and `storage_locations` in the database; optionally `*_FILE` Secrets | column encryption (and SQLCipher in the SQLite flavours); write-only in the interface; step-up for changes; never written to the audit log |

## 2. Actors

| Actor | Capability assumed |
|---|---|
| Anonymous internet user | Reaches the public routes; may hold a share link |
| Share recipient | Holds a link (and maybe a password); can download and preview |
| Authenticated user | Uploads and manages their own shares |
| Guest (reverse-share invite) | Upload-only session for one invite |
| Administrator | Manages users and settings. **Must not read other users' shares.** |
| Auditor | Read-only access to the audit log; can manage nothing |
| Host operator | Root on the server or the container host |
| Disk/backup thief | Has a copy of the volume or a backup, but not the key |
| PostgreSQL administrator or backup reader (Cluster) | Reads and may modify the tenant databases, replicas and backups; does not have the master key or a tenant's KEK |
| Attacker in a `web` pod (Cluster) | Code execution in an internet-facing replica: its memory, its projected ServiceAccount token and its pooler connections; no master key, no provisioner credentials |
| Object storage provider (optional) | Stores, serves and may read, delete, replace or roll back the objects in the bucket; sees access patterns. Does not have the key |
| Network attacker | Between browser and server; Sendora expects TLS in front |
| Platform administrator (multi-tenant and Cluster flavours) | Signs in to the platform console (password + TOTP; TOTP can be switched off by the platform owner): creates, suspends and deletes tenants, sets quotas, domains and storage configuration, forces key rotations and (Cluster) rotates the master key. **Must not read any tenant's users, shares, files, audit details or key material**; sees counts, key modes and fingerprints only |
| Tenant administrator / user of another tenant | Full rights in their own tenant; must gain nothing in any other tenant or in the console |

## 3. Trust boundaries and assumptions

- TLS is terminated in front of Sendora (reverse proxy or Ingress). `SENDORA_TRUSTED_PROXIES` tells which addresses may set `X-Forwarded-For`.
- The server process holds the key in memory. Anyone who controls the running process or the key file can read everything: **Sendora is not end-to-end encrypted.** In the Cluster flavour the master key is only in the controller pods; web pods hold the derived keys of the tenants they serve.
- In the Cluster flavour PostgreSQL, CloudNativePG, the Kubernetes API, etcd and the cluster's RBAC are the operator's and are trusted for availability; the database is not trusted with the column-encrypted content.
- The browser is trusted to run the shipped JavaScript; there is no inline script (CSP `script-src 'self'`).

## 4. Security properties and where they are enforced

| Property | Enforced in | Tested by |
|---|---|---|
| A stolen disk or backup without the key reveals no database content and no share file content (SQLite flavours) | `internal/store/cipher.go`, `internal/filecrypt` | `cipher_params_test.go`, `encryption_e2e_test.go` |
| A reader of the decrypted database (plaintext dump, PostgreSQL administrator, backup reader) sees no plaintext in the encrypted columns; a value copied to another row or changed is refused | `internal/keyring`, `internal/colenc`, the adapters' `encryptedColumns` | `TestStoreConformance` (`internal/conformance`, subtests such as `BoundToTheRow` and `AuditLog`), `TestAuditTextIsSealedUnderAuditEnc` |
| A database whose control log or keys do not verify is not opened (fail closed) | `internal/controllog`, `internal/keyring` | `TestControlLogChainAndMAC`, `TestVerifyDetectsTampering`, `TestVerifyRejectsBadStateTransitions` |
| Key rotation re-encrypts in compare-and-swap batches, and an interrupted key creation is abandoned and redone | `internal/keyops`, `internal/keyring` | `TestTenantKeyRotationAPI`, `TestFilesKeyRotationAPI`, `TestCodecFollowsRotationAndOpensOldVersions`, `stage_crash_test.go` |
| A modified, truncated, extended, reordered or swapped encrypted file is never served as valid data | `internal/filecrypt` (per-chunk tags, last-chunk flag, file ID binding in format v2) | `filecrypt_test.go`, vectors, e2e tamper tests |
| Only the uploader manages a share and reads its download history; administrators cannot | `ownedShare`, `user_id` in every UPDATE | `share_*_test.go`, `stats_privacy_test.go` |
| The administrator statistics contain counts only | `admin.go` stats | `TestAdminStatsDoNotRevealShares` |
| An administrator cannot take over another account silently | admin cannot set a password for others; email change unverifies; MFA reset needs the user's confirmation; user is notified; actions are in the audit log | `TestAdminCannotSetAnotherUsersPassword`, `TestAdminEmailChangeUnverifiesKillsSessionsAndNotifies`, `TestMFAResetNeedsUserConfirmation` |
| Brute force is limited | per-IP rate classes, IP ban, per-account lockout, per-share unlock throttle, setup throttle | `security_test.go` family |
| Tokens cannot be confused | HS256 only, `purpose` claim, per-purpose HKDF subkeys, credential-version claim | auth tests |
| Share files cannot escape their directory | `store.SharePath`, `validateUploadPath`, `validateArchivePath` | `archive_path_test.go` and others |
| Only ciphertext reaches an object store, under keys unrelated to links and names; a tampered database row cannot reach other objects | `putUploadRemote` (encrypt before `Put`), `storage.NewFileKey`, `storage.ValidFileKey`, `store.FileObjectKey`, migration encrypts legacy plain files | storage and migration tests |
| Downloads are verified | SHA-256 recorded at upload, checked before a verified download is served | integrity tests |
| The audit log is append-only and tamper-evident | hash chain under the database's `audit-mac` key, checkpoints, `sendora-db audit-verify` | `TestAuditTamperDetected`, `TestAuditPurgeKeepsChainVerifiable`, `TestAuditTamperDetectedByAPIStatus` |

## 4a. Tenant isolation (multi-tenant mode)

These properties apply to the multi-tenant flavour (`SENDORA_FLAVOUR=multi`, see [MULTI-TENANT.md](MULTI-TENANT.md)); the Cluster flavour uses the same routing, console and per-tenant server code with a PostgreSQL database per tenant, and adds the properties of section 4b. The tests below run on the multi-tenant flavour.

| Property | Enforced in | Tested by |
|---|---|---|
| Each tenant has its own database key: `HKDF-SHA256(master, "sendora/v1/tenant-db/<random id>")`; the platform database uses a separate label; the master key itself encrypts nothing | `internal/store/tenant.go` | `TestKeyDerivationIsDomainSeparated`, `TestPlatformDatabaseIsEncryptedAndRoutes` |
| Tokens, refresh tokens, reset/welcome links, MFA tickets and share links of tenant A are rejected by tenant B (separate database rows and secrets; user IDs overlap on purpose in the test) | one `*app.Server` and store per tenant (`internal/app/mt_host.go`) | `TestMTTenantIsolation` |
| Files and audit chains of A cannot be decrypted or forged with B's keys; WebAuthn RP IDs differ | per-tenant random `files` and `audit-mac` keys in each tenant's keyring, wrapped under the tenant's own KEK | `TestMTTenantIsolation` |
| A request reaches a tenant only through its host; unknown hosts get an identical plain 404; `X-Forwarded-Host` only from trusted proxies | `TenantHost.ServeHTTP`, `requestHost` | `TestMTUnknownHostsArePlain404`, `TestMTForwardedHostOnlyFromTrustedProxies` |
| The console API exists only on `admin.<base>`; tenant tokens are not accepted there; console cookies are host-only and useless on tenant hosts | `mt_console.go` | `TestMTSuspendedTenantAndConsoleSeparation`, `TestMTConsoleLifecycle` |
| Platform administrators need TOTP (default; `platform_mfa_required`); codes cannot be replayed; deleting a tenant or managing administrators needs a fresh code (or, without an authenticator while the platform does not require one, the password). Switching the requirement needs a fresh confirmation and is audited; switching it on ends sessions without a second factor | `mt_console.go` | `TestMTConsoleLifecycle`, `TestMTPlatformMFASwitch` |
| An offline reset of a platform administrator (`sendora-db platform-admin-reset`) is audited; a temporary password only allows choosing a new one | `internal/dbcli/platform_admin.go`, console session middleware | `TestPlatformAdminResetCommand`, `TestMTTemporaryPasswordMustBeChanged` |
| Tenants sharing the platform's bucket write under their own fixed prefix `tenants/<id>/`; each tenant's backend only sees its prefix; objects are encrypted with the tenant's key; deleting a tenant removes its prefix | `platform.Resolve`, `TenantHost.removeTenantObjects` | `TestMTObjectStoragePerTenantOnSharedBucket` (MinIO in CI), `TestTenantStorageOffers` |
| A new tenant has no storage until its administrator sets one up (uploads refused); the platform console and its API never return a tenant's own storage configuration, users beyond counts, share data, audit details or secrets, and cannot change or test the tenant's storage | `platform/storage.go`, `platformConsole.storageView`, `Server.storageAdmits` | `TestMTNewTenantWithoutStorageAndConsolePrivacy` |
| Targets a tenant administrator configures (SMTP, OIDC issuer, audit webhook/syslog, own storage endpoint) cannot reach loopback, private, link-local, CGNAT or metadata addresses: checked when saved and by a dialer on every connection (DNS rebinding); tenant-managed storage cannot use the server's ambient cloud credentials | `internal/netguard`, `Server.guardTargets`, `storage.Config.ValidateTenantManaged` | `TestDialerRefusesLoopbackAtConnectTime`, `TestMTTargetGuardOnSave`, `TestMTTenantManagedStorageAndGuard` |
| The console shows counts only | `platformConsole.view` (no tenant tables are read) | `TestMTConsoleLifecycle` |
| Quotas (users, storage) cannot be bypassed by another code path | trigger `tenant_user_limit`, upload admission | `TestMTQuotas` |
| Suspended tenants are not served | `TenantHost.ServeHTTP` | `TestMTSuspendedTenantAndConsoleSeparation` |
| Every platform action is in the tamper-evident platform audit log, and actions on a tenant in the tenant's log | `platform.Audit`, `RecordPlatformEvent` | `TestMTConsoleLifecycle`, `TestMTSuspendedTenantAndConsoleSeparation` |
| The conversion of a single-tenant installation never loses data and can be resumed or aborted | `internal/platform/import.go` | `TestImportAbortAndResume`, `TestMTImportSingleTenant` |

Residual risks of multi-tenant mode:
- **One process**: a memory-safety or logic bug in the process could cross tenants; tenants share CPU, memory and the process's file descriptors. A busy tenant can slow others.
- **The host operator holds the master key** and can decrypt every tenant offline. Platform administrators (console) cannot; the operator (shell, key file) can.
- **One-time setup links**: without SMTP the console shows the first tenant administrator's set-password link once; whoever sees it could claim that account (it is recorded in both audit logs and the address is only verified by using the link). Configure the platform SMTP server to avoid this.
- **Platform MFA switched off**: with `platform_mfa_required=false` a stolen or guessed console password controls every tenant (create, delete, storage). The default is on; switching it off is the owner's decision and is audited.
- **Allowed private targets**: a tenant for which the platform allows private network targets can make the server connect to internal addresses (SMTP, OIDC, audit forwarding, storage). Allow it only for trusted tenants; it is audited.
- **Shared bucket**: tenants on the platform default share one bucket and its credentials, held by the process. Isolation relies on the per-tenant prefix in the server and on per-tenant encryption, not on bucket policies; an operator who needs provider-side separation configures an own bucket per tenant.
- **Custom domains** are trusted after a DNS TXT check; a domain whose DNS is later taken over keeps routing to the tenant until it is removed in the console.
- **Outbound requests chosen by tenant administrators** (SMTP host, OIDC issuer, audit webhook/syslog) may target private (RFC 1918) addresses, as in single-tenant mode (loopback, link-local and metadata addresses are refused). In a shared platform this lets a tenant administrator probe the platform's internal network; restrict egress with a network policy. These requests cannot reach another tenant: the process routes only by host name and answers a bare IP with 404.
- **Imported tenants**: for a tenant imported from a single-tenant installation whose key differs from the master key, the platform database keeps that key (column-encrypted) as the tenant's legacy root.

## 4b. Cluster flavour (preview)

These properties apply only with `SENDORA_FLAVOUR=cluster` ([cluster/QUICKSTART.md](cluster/QUICKSTART.md), [ENCRYPTION.md](ENCRYPTION.md)).

| Property | Enforced in | Tested by |
|---|---|---|
| Web replicas never hold the master key or provisioner credentials: the start is refused when they are configured, and the key endpoint URL must be `https` | `internal/flavour` | `TestClusterFromEnvErrors` (master key, key endpoint) |
| The key endpoint hands a web replica exactly the derived keys it needs, only for the web ServiceAccount (TokenReview), rate limited, and never writes key material to its log | `internal/keyserver` | `TestWebGetsExactlyTheDerivedKeys`, `TestRejections`, `TestTenantRateLimit`, `TestNoStoreAndNoKeyMaterialInLogs` |
| Each tenant has its own PostgreSQL database and roles; the app role has DML-only grants; a suspended tenant cannot log in | `internal/adapters/postgres` (provisioning) | `TestLiveTenantIsolation`, `TestLiveTenantSuspension` (need a PostgreSQL test database) |
| With a tenant-managed KEK the operator can read neither the tenant's columns nor its files, nor forge its audit chain; the tenant is locked (HTTP 423) after a controller restart until the key is presented on every controller | `internal/keyserver/kek.go`, `internal/app/kek_unlock.go` | `TestTenantManagedFilesAndAuditMACAreNotOperatorReadable`, `TestSwitchToTenantKEKAndLockedUntilUnlocked`, `TestUnlockNeedsEveryController`, `TestLockedTenantAnswers423UntilUnlocked` |
| Wrong keys on the unlock page are limited and audited in the platform log | `internal/keyserver`, `internal/app/kek_unlock.go` | `TestWrongKeyAttemptsAreLimited`, `TestUnlockEndpointIsRateLimited` |
| Master key rotation moves tenants one at a time, resumes after a crash or leader change, and re-wraps without re-encrypting data | `internal/keyserver/master.go` | `TestMasterRotationPlatformManaged`, `TestMasterRotationResumesAfterCrashes`, `TestMasterRotationTenantManagedIsOnlyAMACMove`, `TestMasterRetireRules` |
| Forced rotations by the platform administrator need step-up and a reason, are budgeted and recorded in both audit logs; tenant-managed tenants are skipped in bulk | `internal/app/mt_keys.go` | `TestMTOperatorForcedKeyRotation`, `TestMTMasterKeyConsole` |
| One controller leader at a time | `internal/adapters/k8s` (Lease) | `TestLeaseOneLeaderAndHandover` |

Residual risks of the Cluster flavour:
- **Preview.** Every feature is `preview` until verified in production-like operation ([CAPABILITIES.md](CAPABILITIES.md)).
- **No whole-database encryption.** The PostgreSQL administrator, replicas and backups see IDs, timestamps, statuses, quotas, exact file sizes, slugs, blind indexes, the audit log's action, role, outcome and address, and every column that is not column-encrypted, including the users' TOTP secrets. Encrypt the volumes and backups.
- **Controllers and the master key Secret.** Whoever controls a controller pod, can read the master key Secret (RBAC, etcd) or exec into a controller can read every platform-managed tenant, and the wrapping key of each unlocked tenant-managed tenant.
- **A compromised web pod** yields the derived keys of the tenants it served within the key cache window (`SENDORA_KEY_TTL_SECONDS`, default 600) and can ask for other active tenants while it runs; rate limit, the controller's log and the short-lived token are the brakes.
- **Tenant-managed keys**: losing the key loses the tenant's data, backups included; every controller restart locks the tenant until the key is presented again.
- **Master key version 1** still derives the database role passwords and the platform's own keys and cannot be retired.
- **Key endpoint requests** are logged in the controller's process log, not in a tamper-evident audit chain.

## 5. Threats and residual risk

### 5.1 Disk, backup or snapshot theft (no key)
Mitigated for the database (SQLite flavours), for share files and for backups. In the Cluster flavour only the column encryption and the file encryption apply: a copy of the PostgreSQL volume or backup reveals the metadata and the columns that are not column-encrypted (see 4b). **Residual:** files uploaded before 0.1.2; upload parts in progress and temporary download snapshots (plain, short-lived); branding images; file names, sizes, counts and modification times (no padding). **Share link IDs are the folder names under `DATA_DIR/shares/`**, so a key-less copy of the volume reveals them: with a link ID a share can be opened as long as it is active and has no password. Protect the volume and its snapshots accordingly, use share passwords for sensitive data, and keep expiry short.

### 5.1a Object storage provider (optional)
With `storage_backend` set to `s3`, `azure` or `gcs`, share files are encrypted **before** they leave the server; the provider only receives ciphertext under random names (`files/<32 hex>`), so this setup avoids the 5.1 residuals for those files: no link IDs, no file names in object names, no plain legacy files (migration encrypts them). Remote backup copies are the SQLCipher backups (SQLite flavours). The provider sees object sizes (plaintext size + 53 + 16 per 64 KiB, no padding), counts, write/read/delete times and request addresses, and could correlate uploads made at the same moment.
- **Tampering** (modified, truncated, extended, reordered chunks, an object copied over another): detected by the GCM tags and the file-ID binding of format v2; the download is refused (409) and `file_decrypt_failed` is recorded. A migration verifies every copy completely before switching.
- **Deletion, withholding or rollback** of objects (or of a whole bucket): an availability risk, not a confidentiality risk. `sendora-db verify-files` reports missing or failing objects; objects are never overwritten by Sendora (every write uses a new random key), so a rollback can only remove data. Use provider versioning/soft delete and monitoring (see [STORAGE.md](STORAGE.md#9-recommended-bucket-settings)).
- **Credentials** are stored column-encrypted in the database (per location, so old files stay readable after a switch) or come from `*_FILE` Secrets or workload identity. They are write-only in the interface and never audited. Changing a storage setting, testing a connection and starting a migration need a step-up. A stored secret is sent only to the endpoint/account it was entered for: changing the endpoint, account or access key requires entering it again, so a stolen administrator session cannot redirect it (relevant for GCS, where bearer tokens are sent to the endpoint). Plain `http://` endpoints are accepted only for loopback, private and cluster-internal hosts.
- **Residual:** the provider learns sizes, timing and access patterns; versioned or soft-deleted copies of deleted or erased files persist at the provider until their retention ends (still encrypted, but decryptable with the tenant's `files` key); whoever holds both a copy of the bucket and the keys (the database and the key that derives its KEK) can read everything; a provider outage makes downloads (503) and uploads fail; credentials with more rights than needed (an Azure account key, a broad IAM policy) widen the impact of a server compromise.

### 5.2 Malicious or compromised administrator
- Cannot read shares, download history or share names through the interface or the API (statistics are counts). The audit log is readable by administrators and auditors alike; it names shares only as `share#N`, so an administrator can see when shares are created, changed or downloaded and by whom, but not what they are called or what they contain. Every export of the log and every backup download is recorded before it is served.
- Cannot silently take over an account (see 4), cannot switch off or wipe the audit log, cannot read key material (Admin → Keys shows versions, states and fingerprints only).
- **Residual:** an administrator can still delete a user (and so that user's shares), change settings (including the storage backend, after a step-up: new files then go to another bucket), import a database and, with access to the host, everything the host operator can. Administrators can see user names and email addresses.

### 5.3 Host operator or memory access
Not defended. The key and plain data are in process memory; the key file is readable by the service account. In the Cluster flavour this applies to the controller pods (master key) and, for the tenants they serve, to the web pods; tenant-managed tenants are protected against an operator who does not control a running controller. Mitigations are operational: disable core dumps, restrict host access, keep the key apart from the data, forward the audit log off the host (standard output, syslog or webhook with a periodic chain-head heartbeat; see [configuration](configuration.md#forwarding-the-audit-log)).

### 5.4 Account attacks
Credential stuffing, password guessing, MFA bypass, session theft. Mitigated by bcrypt (cost 12), lockout, IP bans, TOTP and WebAuthn, rotating refresh tokens with reuse detection, short access tokens (15 min), absolute session limit (30 days), a minimum of 8 characters with screening of common, personal and trivial passwords (optionally the Have I Been Pwned range API, k-anonymity), email notifications about password, factor and recovery-code changes and sign-ins from new browsers or networks, and step-up re-authentication plus an optional network allowlist for critical administrator actions. A stolen administrator session therefore cannot delete users, change roles, providers or security settings, or download backups without the password or second factor. **Residual:** account lockout can be used to annoy a known username; OIDC logins rely on the identity provider's own MFA.

### 5.5 Share link attacks
Link guessing (86 bits, 404/410 uniform), password guessing (bcrypt, per-IP and per-share throttle), download-slot exhaustion (bounded; see known limits), recipients forwarding links (inherent to link sharing; expiry, download limits and passwords are the controls).

### 5.6 Web attacks
XSS (no inline script, strict CSP, escaped rendering, validated theme/translation imports), CSRF (`Sec-Fetch-Site`/`Origin` check, bearer-token authorisation), clickjacking (`frame-ancestors 'none'`), content sniffing (`nosniff`, downloads are `application/octet-stream` attachments, previews only for a type allowlist with `CSP default-src 'none'; sandbox`), SSRF through the OIDC issuer (loopback and link-local targets refused).

### 5.7 Supply chain
SQLCipher 4.20.0 is built from a checksum-verified source tarball. Base images are pinned by digest (Debian 13 "trixie" runtime) and kept current by Dependabot; apt packages are not version-pinned. Release images carry build-provenance and SBOM attestations and a cosign signature (from 0.1.5). Go modules are pinned by `go.sum`.

### 5.8 Personal data and erasure
Users can export their own data and delete their account; administrators can erase an account. Erasure deletes shares, files, invites, sessions, second factors and linked sign-ins and pseudonymises the account row (`erased-<id>`, no name, email or password). **Legitimate-interest exception:** audit records written while the account existed keep their `actor_name` (the former username) and target labels. They are not rewritten because the audit log is a tamper-evident chain kept for the security of the service and the accountability of administrators (GDPR art. 6(1)(f); art. 17(3)(e) for legal claims). They are removed by the normal retention (`audit_retention_days`, 90 to 365 days). Backups made before the erasure still contain the account until they are rotated out (`backup_keep`, also for remote backup copies). Files in an object store are deleted through a queue right after the erasure (retried while the store is unreachable); copies kept by the provider's versioning or soft delete remain until their retention ends.

## 6. Known limits (documented, not fixed)
- SQLite flavours: the root key is used raw by SQLCipher and the KEK is derived from it, so the key file opens every key. Share files written by 0.2 used a key derived from the root; they are refused until the `files-reencrypt` job converts them to the tenant's `files` key.
- The data, index, secrets, files and audit-enc keys rotate online (Admin → Keys, `sendora-db rotate-key`); rotating the files key rewrites every stored file in a background job. The audit-mac key stays at version 1.
- The users' TOTP secrets are not column-encrypted (the platform administrators' are).
- No external KMS or HSM; no independent journal or WORM anchors for the control log and the audit chain: an attacker who can rewrite the whole database and holds the keys could rebuild a consistent chain.
- Whole-database rollback or page replay is not detected.
- Plain upload parts and download snapshots on disk during transfers (also with an object store: parts are assembled and encrypted locally).
- Object sizes and access patterns are visible to an object storage provider (no padding).
- Verified-download slots are global (3) and can be held by a client that reads slowly.
- Not independently audited.
