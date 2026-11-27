# Shared responsibility matrix

Sendora is self-hosted software, not a service: the organisation that deploys it (the "operator" or "customer") runs the infrastructure and the processes around it. This matrix states, per control area, what the Sendora application provides, what the operator must do, and what evidence Sendora can produce for an audit. It is organised by the ISO/IEC 27001:2022 Annex A themes and the SOC 2 Trust Services Criteria. It does not certify anything: Sendora has **not** been independently audited, and an operator's certification depends on the operator's own controls.

Written for version 0.2.0 (object storage rows and section 4a came with 0.2.0). The Cluster flavour of 0.3 is not covered yet ([cluster/QUICKSTART.md](../cluster/QUICKSTART.md), [ENCRYPTION.md](../ENCRYPTION.md)).

[Back to the compliance index](README.md)

Legend: **Provided** = implemented in the application; **Operator** = customer responsibility; **Gap** = not provided by Sendora and not something the operator can switch on in it.

## 1. Evidence Sendora can produce

| Evidence | How to obtain | Content |
|---|---|---|
| Audit log | Admin → Audit log, or `GET /api/audit` (administrators and auditors) | Tamper-evident record of authentication, account, administrative, share and system events ([AUDIT-EVENTS.md](AUDIT-EVENTS.md)) |
| Audit export | `GET /api/audit/export?format=csv` or `jsonl` (also `/api/logs/export`) | All fields including `seq`, `prev_hash`, `hash`, with filters; the export itself is audited |
| Chain verification | `GET /api/audit/status`; readiness check `audit_chain`; offline `sendora-db audit-verify -source <db> -key-file <key> [-json]` | Whether the chain verifies, first broken record, count, checkpoint |
| Off-host audit copy and heartbeat | Forwarding to stdout, syslog or webhook; `chain_head` every 5 minutes | Records plus chain head for gap and truncation detection at the receiver |
| Access-review report | Admin/Auditor → Access review, `GET /api/access-review`, export `GET /api/access-review/export?format=csv` or `jsonl` (audited) | Every account (except guests): role, sign-in sources, MFA enrolment and policy, created/role/email changes with who and when, last sign-in, lock and disable state, share count and storage (no share names) |
| File integrity report | `sendora-db verify-files -source <db> -key-file <key> -data-dir <dir> [-json] [-all]` | Header, size, file ID, every chunk tag and SHA-256 of every stored file, local or in an object store; orphan files and orphan objects |
| Storage location and migration evidence (0.2.0) | Admin → Storage; audit events `storage_*`, `backup_remote_*` | Current backend, files and bytes per location, pending deletions, migration history with counts |
| Database verification | `sendora-db verify` | Opens the database with the key and reports counts |
| Personal-data export | Profile → Your data (`GET /api/users/me/export`) | A user's own data (see [PERSONAL-DATA.md](PERSONAL-DATA.md)) |
| Configuration evidence | Admin → Settings (managed values marked), `SENDORA_*` variables in your deployment repository; changes are in the audit log as `settings_changed` with old and new values (secrets by name only) | Effective security settings |
| Readiness and metrics | `GET /api/health/ready`, `GET /api/metrics` (token) | Database, audit write state, disk, backup age, chain; sign-in, MFA, decrypt, ban, download and upload counters |
| Supply-chain evidence (0.1.5 onwards) | `cosign verify`, `gh attestation verify` ([SECURITY.md](../../SECURITY.md#verifying-release-images)) | Keyless signature, build provenance, SPDX SBOM per image digest |
| Development evidence | GitHub Actions runs, code scanning (CodeQL, Trivy), Dependabot pull requests | Test, scan and update history |

## 2. ISO/IEC 27001:2022 Annex A

### 2.1 Organisational controls (A.5)

| Control area | Sendora provides | Operator must | Evidence |
|---|---|---|---|
| Policies, roles, segregation of duties (5.1–5.4) | Roles `user`, `admin`, `auditor` (read-only, mutually exclusive with admin), `guest`; administrators cannot read users' shares | Write the policies; assign administrator and auditor roles to named people; define who approves role changes. **Gap:** no four-eyes approval in the application | Access-review report; `user_role_changed` events |
| Threat intelligence (5.7) | Security advisories through GitHub | Subscribe to releases and advisories | — |
| Information security in projects / supplier relationships (5.8, 5.19–5.23) | Open source code, threat model, this documentation, signed images from 0.1.5; optional object storage receives ciphertext only ([STORAGE.md](../STORAGE.md)) | Assess Sendora as a supplier component; there is no vendor contract, SLA or support. If you use an object storage provider: assess it as a (sub-)processor of encrypted data, choose the region, sign its DPA | This folder, [THREAT-MODEL.md](../THREAT-MODEL.md) |
| Asset inventory, acceptable use, classification, labelling (5.9–5.13) | Data inventory ([PERSONAL-DATA.md](PERSONAL-DATA.md)); optional terms acceptance with versioning | Inventory the deployment; classify what may be shared; publish acceptable-use terms. **Gap:** no classification labels on shares, no content inspection or DLP | `terms_accepted` events |
| Information transfer (5.14) | Expiring links, download limits, optional/required share passwords with policy, download notifications to the owner | Decide policy values (`max_expiry_time`, `require_share_password`, ...); TLS in front | Settings; share events |
| Access control, identity, authentication (5.15–5.17) | Local accounts, MFA (TOTP, WebAuthn; policies `off`/`optional`/`admins`/`privileged`/`all`), OIDC/Entra/Google/GitHub, local login can be disabled, lockout, IP bans, step-up for critical admin actions, admin IP allowlist, session limits | Run the identity provider and its MFA; joiner/mover/leaver process; disable accounts at the IdP and in Sendora; set MFA policy | Access-review report; auth events |
| Access rights and reviews (5.18) | Access-review report and export; disable/enable accounts; sign users out everywhere | Perform periodic reviews as a **process** (Sendora produces the report, it does not schedule or sign off reviews) | Exported report; `access_review_exported` events |
| Incident management (5.24–5.28) | Audit log, forwarding, heartbeat, metrics, security notifications to users | Incident process, alerting, forensics, notification of authorities and data subjects | Audit export, forwarded logs |
| Business continuity, ICT readiness (5.29–5.30) | Automatic encrypted database backups (daily, `backup_keep`), optionally copied to the object store (`backup_remote_enabled`); readiness check for backup age | Back up the **whole volume** (share files are not in Sendora's backups) and the key off-host; with an object store, protect share files with provider versioning/soft delete or replication; test restores; DR plan. **Gap:** no HA, single instance | `backup_*` events; readiness `backup` |
| Legal, privacy, PII (5.31–5.34) | GDPR export, erasure, rectification; IP logging off by default; privacy/terms links | Legal assessment, privacy notice, records of processing, DPIA, retention decisions. **Gap:** no legal hold | [PERSONAL-DATA.md](PERSONAL-DATA.md) |
| Independent review, compliance (5.35–5.36) | — | Commission reviews of your deployment. **Gap:** Sendora itself is not independently audited or penetration tested | — |
| Documented procedures (5.37) | Configuration, quick starts, hardening guide (wiki), this folder | Write your runbooks | — |

### 2.2 People controls (A.6)

| Control area | Sendora provides | Operator must | Evidence |
|---|---|---|---|
| Screening, terms, awareness, disciplinary, termination (6.1–6.5) | Terms acceptance; account disable with reason; erasure | All HR processes; revoke access at termination | `user_disabled`, `terms_accepted` |
| Confidentiality agreements, remote working, event reporting (6.6–6.8) | Security-notification emails let users notice account changes | Agreements, remote-work policy, reporting channel | — |

### 2.3 Physical controls (A.7)

| Control area | Sendora provides | Operator must | Evidence |
|---|---|---|---|
| Physical security, equipment, storage media, disposal (7.1–7.14) | Database, backups and new share files encrypted at rest, so a lost disk without the key reveals no contents | Data-centre or cloud physical security; secure disposal; keep the key off the data media | — |

### 2.4 Technological controls (A.8)

| Control area | Sendora provides | Operator must | Evidence |
|---|---|---|---|
| User endpoint devices (8.1) | — | Endpoint management | — |
| Privileged access (8.2) | Admin role separate from auditor; step-up; admin idle timeout 15 min; IP allowlist; admins cannot set other users' passwords or read shares | Limit administrator accounts; require MFA (`mfa_policy=admins` or `all`) or IdP MFA | Access-review report; `stepup_*` events |
| Information access restriction (8.3) | Owner-only share management; route access matrix test | — | Test results in CI |
| Access to source code (8.4) | Public repository | Protect your deployment repository and secrets | — |
| Secure authentication (8.5) | bcrypt 12, password screening, optional HIBP check, MFA, lockout, IP bans, rotating refresh tokens with reuse detection, 30-day absolute session limit; optional maximum password age (`account_password_max_age_days`, 365 days on new installations, off after an upgrade) with reminders and per-account exemption; password history (`account_password_history`, last 5 by default) | IdP configuration; enable HIBP if allowed by your policy; decide whether your policy requires periodic password changes (NIST SP 800-63B advises against forced rotation without cause; prefer screening and MFA) and set the maximum age accordingly, including on upgraded installations where it starts at 0; keep exemptions few and review them | Auth events (`password_expired`, `password_expiry_warning_sent`), `password_rotation_exempt_changed`, access-review columns `password_age_days`, `password_rotation_exempt`, `password_expires_at` |
| Capacity management (8.6) | Per-user storage quotas, share size limit, readiness disk check, metrics | Size storage and monitor | Readiness, metrics |
| Protection against malware (8.7) | Downloads served as attachments with `nosniff`; previews only for an allowlist of image/video/audio types in a sandboxed CSP | Scan files at the edge or on endpoints. **Gap:** no malware scanning of uploads | — |
| Technical vulnerabilities (8.8) | CI scanning, Dependabot, weekly Trivy, patch releases ([VULNERABILITY-AND-DEPENDENCY-MANAGEMENT.md](VULNERABILITY-AND-DEPENDENCY-MANAGEMENT.md)) | **Patching:** update to the latest release; patch host, runtime, proxy | Release history; code scanning |
| Configuration management (8.9) | Settings from environment/ConfigMap override and lock the admin screen; invalid values stop the server; startup checks for risky configuration and secret file permissions | Keep configuration in version control; review changes | `settings_changed`; startup log |
| Information deletion (8.10) | Expiry, automatic clean-up after `clean_files_days`, erasure; remote objects are queued for deletion in the same transaction and retried | Set retention; delete volume backups per policy; align object-store versioning/soft-delete retention with your erasure statements | `share_files_purged`, `user_erased` |
| Data masking (8.11) | Audit log uses `share#N`; statistics are counts; secrets never logged | — | Audit export |
| Data leakage prevention (8.12) | Owner-only access; admins cannot open shares | **Gap:** no DLP or content inspection | — |
| Backup (8.13) | Daily encrypted DB backups, pre-import backup, `sendora-db backup`; optional remote copies in the object store | Back up volume and key separately and off-host; test restore; keep the database key out of the object store | `backup_*` events |
| Redundancy (8.14) | — | **Gap:** single instance; redundancy only at the storage/platform level | — |
| Logging (8.15) | Tamper-evident audit log, 90–365 days, forwarding, heartbeat | Retain forwarded logs as long as your policy requires; protect the receiver | Chain verification, exports |
| Monitoring (8.16) | Readiness, Prometheus metrics, forwarding status | **Monitoring/SIEM:** alerting, correlation, on-call | Metrics, `/api/audit/status` |
| Clock synchronisation (8.17) | Audit timestamps in UTC from the host clock | NTP on hosts | — |
| Privileged utilities (8.18) | `sendora-db` works offline with the key | Restrict host access; offline tool use is **not audited** | — |
| Software installation (8.19) | Signed images (from 0.1.5) | Deploy by verified digest; admission policy | cosign / attestation output |
| Network security, segregation, web filtering (8.20–8.23) | Trusted-proxy handling; SSRF guards on outbound OIDC and forwarding; object-store endpoints https-only (http only for private hosts); example NetworkPolicy | **Network:** TLS termination, firewalling, egress restriction (including the object store), protect the proxy→Sendora hop; private, TLS-only bucket policy | — |
| Cryptography (8.24) | SQLCipher, AES-256-GCM files (encrypted before upload to an object store), HMAC chain, HKDF subkeys ([FILE-FORMAT.md](../FILE-FORMAT.md)) | **TLS** in front; **storage encryption** of the volume (plain staging data, names on disk); **key custody** (32-byte key file, separate backup, access control); object-store credentials: least privilege, rotation, workload identity where possible. **Gap:** no key rotation, no HSM/KMS | Startup log `file encryption active fp=…` |
| Secure development (8.25–8.29, 8.31–8.33) | Tests incl. route access matrix, fuzz/property tests, CodeQL, govulncheck, npm audit, pinned actions/images, release gating | Test your deployment and upgrades in a non-production environment | CI history |
| Outsourced development (8.30) | Development is by a single maintainer with an AI assistant | Assess this as a risk | [SECURITY.md](../../SECURITY.md) |
| Change management (8.32) | CHANGELOG; versioned releases | Change process for upgrades and configuration | — |
| Test information (8.33) | — | Do not use production data in tests | — |
| Audit testing protection (8.34) | Auditor role is read-only; exports audited | Plan audit access | `audit_viewed`, `audit_exported` |

## 3. SOC 2 Trust Services Criteria

| Criteria | Sendora provides | Operator must | Evidence |
|---|---|---|---|
| **CC1** Control environment | — | Governance, ethics, HR, oversight | — |
| **CC2** Communication and information | Security notifications to users; documentation; audit log for internal information | Communicate policies to users; privacy and terms pages (`privacy_url`, `terms_url`) | `terms_accepted` |
| **CC3** Risk assessment | [THREAT-MODEL.md](../THREAT-MODEL.md), known limitations | Risk assessment of the deployment | — |
| **CC4** Monitoring activities | Chain verification, readiness, metrics, access-review report | Periodic control testing and review | Status endpoints; exports |
| **CC5** Control activities | Enforced settings from configuration; step-up; critical-action pre-audit | Select and deploy controls; document procedures | Settings; audit |
| **CC6.1** Logical access, encryption | RBAC, MFA, SSO, encryption at rest | IdP, TLS, storage encryption, key custody | Access-review report |
| **CC6.2 / CC6.3** Provisioning, changes, removal | Admin user management, disable, erase, role changes audited; provider session limit (24 h) propagates IdP disablement | Joiner/mover/leaver process; **access reviews as a process** | `user_*` events; access-review export |
| **CC6.6** External threats | Rate limits, IP bans, lockout, CSP, CSRF checks, SSRF guards | Proxy/WAF, DDoS protection, network controls | `ip_banned`, metrics |
| **CC6.7** Transmission | Outbound TLS for SMTP (default STARTTLS), syslog (default TLS), webhook (HTTPS) | **TLS termination** for all user traffic | — |
| **CC6.8** Malicious software | Safe download headers, preview allowlist; signed images | **Gap:** no malware scanning; operator scans at the edge | — |
| **CC7.1** Vulnerability detection | CI scans, weekly CodeQL and Trivy, Dependabot | Scan your environment; **patching** | Code scanning |
| **CC7.2** Anomaly monitoring | Audit log, forwarding, heartbeat, metrics | **SIEM**, alert rules (for example `login_lockout`, `ip_banned`, `access_denied`, `file_decrypt_failed`, `key_fingerprint_changed`, `audit_purge_failed`, chain head moving backwards) | Forwarded records |
| **CC7.3–CC7.5** Incident evaluation, response, recovery | Session revocation, account disable, IP bans, MFA reset flow, backups, `verify-files` | Incident response plan and execution, communication | Audit export |
| **CC8.1** Change management | Versioned, signed releases; settings changes audited with old/new values | Approve and test upgrades and configuration changes | `settings_changed` |
| **CC9.1** Business disruption | Backups and readiness | BCP/DR, volume and key backups, restore tests | — |
| **CC9.2** Vendor risk | This documentation, SBOM, provenance | Assess Sendora and its dependencies; no vendor SLA | SBOM attestation |
| **A1** Availability | Readiness/liveness probes, graceful shutdown, daily DB backups | Capacity, HA at platform level, backups of the volume, monitoring. **Gap:** single instance, no SLA | Readiness, metrics |
| **C1** Confidentiality | Encryption at rest, owner-only access, expiry and clean-up, admins cannot read shares | Classification policy, TLS, storage encryption, key custody, volume-backup protection | Settings, `share_files_purged` |
| **PI1** Processing integrity | SHA-256 at upload and verified downloads; authenticated encryption detects modified files (409, `file_decrypt_failed`); `verify-files` | Run `verify-files` periodically; investigate failures | `verify-files` output |
| **P** Privacy | Export, erasure, rectification, IP minimisation, retention, terms/privacy links ([PERSONAL-DATA.md](PERSONAL-DATA.md)) | Notice, consent where needed, DSR process for data outside Sendora (backups, forwarded logs, proxy logs). **Gap:** no legal hold | `personal_data_exported`, `user_erased` |

## 4. Operator responsibilities in one list

- **Infrastructure:** host or cluster, container runtime, storage, patching of all of it.
- **TLS:** terminate HTTPS in front of Sendora; set `APP_URL` and `SENDORA_TRUSTED_PROXIES`.
- **Storage encryption:** encrypt the data volume (upload parts, download snapshots, file names and link IDs in directory names are not encrypted by Sendora).
- **Backups of the volume:** Sendora's backups cover the database only; back up share files, database backups and the key (separately) off-host and test restores.
- **Network:** firewalling, egress restriction, protection of the proxy→Sendora hop.
- **Identity provider:** configuration, MFA, conditional access, leaver process.
- **Monitoring/SIEM:** collect forwarded audit records, alert, retain, check the heartbeat.
- **Key custody:** generate, store, back up and restrict the 32-byte key; there is no rotation once files exist.
- **Patching:** update Sendora to the latest release; verify image signatures (0.1.5+).
- **Access reviews as a process:** export the report regularly, review, act, keep the evidence.

## 4a. Multi-tenant mode (optional, 0.2.0)

When one installation serves several organisations, the **platform operator** runs Sendora for the tenants and the tenants act as controllers for their own users and shares.

| Area | Sendora provides | Platform operator | Tenant |
|---|---|---|---|
| Isolation between tenants | separate encrypted database, directory, keys and secrets per tenant; isolation tests | runs one process per platform, protects the master key, keeps the image current | — |
| Platform access | console with TOTP required by default (`platform_mfa_required`; switching it off is audited), step-up for destructive actions, platform audit log, offline `platform-admin-reset` (audited) | manages platform administrators, decides on the MFA requirement, reviews the platform audit log | — |
| Tenant administration | each tenant's own admin screens, audit log, backups | sets quotas and domains; never needs tenant content | manages users, settings, SMTP, providers, retention |
| Storage | per-tenant storage: own S3/Azure/GCS (explicit credentials, SSRF-guarded endpoint) or a platform offer (platform bucket under a fixed prefix, or local disk); per-tenant storage limit for platform storage; encryption with the tenant's own file key | decides whether a tenant may use its own storage and what it offers; operates the platform bucket; sets storage limits | configures and pays for its own storage, its retention, versioning and region |
| Network targets | SSRF guard for tenant-configured SMTP, OIDC, audit forwarding and storage endpoints; per-tenant exception (audited in both logs) | allows private targets only where needed | — |
| DNS and TLS | DNS TXT verification of custom domains | wildcard certificate, ingress, custom-domain certificates | creates the DNS records for its custom domain |
| Backups | per-tenant automatic backups; offline restore procedure | backs up the whole `DATA_DIR` and the master key, restores on request | downloads its own backups |
| Email | per-tenant SMTP; platform SMTP as default | operates/contracts the default SMTP server | may configure its own SMTP |
| Agreements | — | data processing agreement with each tenant (processor, art. 28 GDPR) | controller for its users' data |

## 5. Gaps (not provided by Sendora)

| Gap | Consequence / mitigation by the operator |
|---|---|
| No malware or content scanning of uploads | Scan at the edge, on endpoints, or with a separate service |
| No DLP / classification labels | Policy and training; restrict who may upload |
| No four-eyes (dual-control) approval for administrator actions | Limit administrators; review the audit log; step-up and pre-audit records exist |
| No legal hold or e-discovery | Preserve volume backups and forwarded logs outside Sendora |
| No high availability, single instance | Platform-level restart and storage redundancy |
| No native TLS | Reverse proxy or Ingress |
| No key rotation, no HSM/KMS | Strict key custody; plan for re-deployment if the key is compromised |
| Most offline `sendora-db` actions are not audited (`storage-migrate`, `tenant-import` and `platform-admin-reset` are) | Restrict and log host access |
| No scheduled access reviews or sign-off workflow | Run reviews as a process with the exported report |
| No SLA, support contract or security team | Assess as supplier risk |
| Not independently audited or penetration tested | Commission your own assessment |
