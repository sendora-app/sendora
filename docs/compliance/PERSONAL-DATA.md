# Personal data inventory

This inventory lists the personal data Sendora stores, why, where, how it is protected, how long it is kept and how it is deleted, so that a controller can prepare its record of processing activities (GDPR art. 30), a DPIA, and answers to data-subject requests. The operator of a Sendora deployment is the controller; this document describes what the software does, not the operator's legal assessment. The "legal basis" column is only a hint.

Written for version 0.2.0; object storage and multi-tenant mode are optional. The Cluster flavour of 0.3 is not covered yet ([cluster/QUICKSTART.md](../cluster/QUICKSTART.md), [ENCRYPTION.md](../ENCRYPTION.md)).

[Back to the compliance index](README.md)

## 1. Where data lives

| Location | Protection at rest |
|---|---|
| Database `DATA_DIR/sendora.db` (all tables below) | SQLCipher (AES-256), key from `SENDORA_DB_KEY_FILE` |
| Share files `DATA_DIR/shares/<link id>/<index>_<file name>` | File contents AES-256-GCM (since 0.1.2); **directory and file names are not encrypted** |
| Upload staging `DATA_DIR/uploads/` and download snapshots `DATA_DIR/.verified-download-*` | Not encrypted; short-lived (see section 3) |
| Share files in an object store (optional: S3-compatible, Azure Blob, GCS) `<prefix>files/<32 random hex>` | Encrypted before upload (AES-256-GCM, format v2); object names are random and reveal no names or link IDs. The provider sees sizes and times (sub-processor of encrypted data, see [STORAGE.md](../STORAGE.md)) |
| Database backups `DATA_DIR/backups/` | SQLCipher, same key |
| Remote backup copies `<prefix>backups/` (optional, `backup_remote_enabled`) | SQLCipher, same key; pruned with `backup_keep`; copies kept by provider versioning or soft delete remain until their retention ends |
| Forwarded audit records (stdout, syslog, webhook) | Whatever the receiving system provides |
| Process log (stdout/stderr) | Operational messages; no HTTP access log. Error texts from external systems (for example SMTP replies) are logged as received |
| Outgoing email | Leaves Sendora's control at the SMTP server |
| Reverse proxy logs | Operator's system (client IPs, URLs including share link IDs) |

## 2. Inventory

Legal basis hints: **C** = contract / provision of the service requested (GDPR art. 6(1)(b)); **LI** = legitimate interest in security and accountability (art. 6(1)(f)); **Consent/choice** = data the user chooses to provide.

| Data (table.field) | Data subject | Purpose | Basis | Encrypted at rest | Retention | Deletion / erasure |
|---|---|---|---|---|---|---|
| `users`: `username`, `name`, `email`, `email_verified`, `language`, `ui_language`, `created_at` | Account holder | Account, sign-in, notifications | C | Yes (DB) | Life of the account | User erasure or admin erasure pseudonymises (`erased-<id>`, name/email cleared); admin deletion removes the row |
| `users.password_hash` | Account holder | Local sign-in (bcrypt) | C | Yes (DB) + hashed | Life of the account | Cleared on erasure |
| `users`: `password_changed_at`, `password_expiry_warned_at`, `password_rotation_exempt` | Account holder | Password maximum age (`account_password_max_age_days`), the one-time expiry reminder, administrator exemption; shown in the access review | C / LI | Yes | Life of the account; `password_expiry_warned_at` is cleared at every password change | Cleared on erasure |
| `password_history`: bcrypt hashes of earlier local passwords, `created_at` | Account holder | Refuse reuse of the last `account_password_history` passwords (default 5) | LI | Yes (DB) + hashed (bcrypt cost 12, never the password) | Only the newest N per account (N = `account_password_history`, max. 24); older rows are deleted at the next password change, and all of them when N is 0 | Deleted on erasure; removed with the account on deletion |
| `users`: `admin`, `is_auditor`, `mfa_policy`, `quota_*`, `must_change_password`, `login_failures`, `login_locked_until` | Account holder | Authorisation, security | C / LI | Yes | Life of the account | Reset on erasure |
| `users`: `created_by`, `role_changed_at/_by`, `email_changed_at/_by`, `disabled_at/_by/_reason`, `last_login_at` | Account holder; the administrator named in `*_by` (`user#N (name)`) | Access review, accountability | LI | Yes | Life of the account | **Not cleared on erasure** of the account; the administrator's name in other accounts' `*_by` fields is not changed when that administrator is erased. `disabled_reason` is free text typed by an administrator |
| `users`: `terms_accepted_version`, `terms_accepted_at` | Account holder | Proof of acceptance of the operator's terms | C | Yes | Life of the account; asked again when `terms_version` changes | Cleared on erasure |
| `users.erased_at` | Former account holder | Marks a pseudonymised account | LI | Yes | Permanent (row kept so IDs keep resolving) | — |
| `user_auth_providers.provider_user_id` | Account holder | Link to the identity provider account (subject ID) | C | Yes | Until unlinked | Deleted on erasure, unlink or deletion |
| `user_totp.secret` | Account holder | TOTP second factor | C / LI | Yes (DB; secret itself not additionally encrypted) | Until removed | Deleted on removal, MFA reset, erasure |
| `user_recovery_codes.code_hash`, `used_at` | Account holder | Recovery codes | C / LI | Yes + hashed | Until regenerated or removed | As above |
| `user_webauthn`: credential ID, public key, `name`, `created_at`, `last_used_at` | Account holder | Passkeys / security keys | C / LI | Yes | Until removed | As above |
| `refresh_tokens`: token hash, `user_agent` (max. 200 chars), `ip` (**only while `audit_log_ip` is on**), `auth_method`, `session_started`, `issued_at`, `expires_at` | Account holder | Sessions, session list for the user | C / LI | Yes + token hashed | Until sign-out, revocation or expiry; at most **30 days** (absolute) | Deleted on sign-out, revocation, credential change, disable, erasure; expired rows removed by the maintenance job (every 10 min) |
| `refresh_spent`: token hash, `spent_at` | Account holder | Detection of refresh-token reuse | LI | Yes | Until the token's expiry | Maintenance job; erasure |
| `revoked_access_tokens`: token hash | Account holder (indirect) | Immediate revocation of access tokens | LI | Yes | Until expiry (≤15 min) | Maintenance job |
| `user_signin_seen`: keyed hash (HMAC) of user ID + browser family + network (/16 IPv4, /48 IPv6), `last_seen` | Account holder | "New sign-in" notification | LI | Yes; no raw address or user agent stored | **30 days**, max. 20 entries per account | Pruned at each sign-in; deleted on erasure |
| `password_resets`, `email_verifications`, `verification_attempts`, `mfa_reset_requests` | Account holder | Reset (1 h), email verification code (30 min), MFA reset confirmation (24 h, requester ID) | C / LI | Yes; reset and MFA-reset tokens hashed | Until used or expired | Expired reset, verification and attempt rows removed by the maintenance job; expired `mfa_reset_requests` rows (hash, user ID, requester ID) stay until the next request, confirmation, disable or erasure |
| `shares`: `name`, `description`, password hash, limits, `expires_at`, `created_at`; `files`: `name`, `full_path`, `size`, `type`, SHA-256 | Uploader; persons named in names, descriptions or file names | Provide the share | C | Yes (DB) | Until deleted by the owner, or **`clean_files_days` (default 7) after expiry** while `auto_clean_files` is on (default on) | Deleted with the share, the account (deletion/erasure) |
| File contents | Uploader; anyone in the files | Provide the share | C | AES-256-GCM (since 0.1.2) | As the share | As the share |
| `downloads`: `share_id`, `file_id`, `created_at`, `ip` (**only while `audit_log_ip` is on**) | Recipient | Owner's download history (times and files; the address is never shown), download limits | C / LI | Yes | **90 days** | Maintenance job; stored addresses are blanked when `audit_log_ip` is off; deleted with the share |
| `reverse_invites`: `recipient_name`, `recipient_email`, `message`, `token` (plain), dates | Invited guest; inviter | Reverse-share invitation | C | Yes (DB); token not hashed | Email invitations: **no automatic deletion** (kept after expiry until the inviting account is deleted or erased). Open-link child invitations expired unused: removed by the maintenance job | Deleted on inviter deletion/erasure |
| Guest accounts (`users` with `is_guest=1`: generated username, display name) | Guest | Upload session for one invitation | C | Yes | Guests of expired, unused open-link invitations: removed by the maintenance job. Other guest accounts: kept until the inviting account is deleted or erased | As stated |
| `download_mail_outbox`: `recipient` (owner email), language, share name, file names, download count, `last_error` | Share owner | Download notification email | C | Yes | Deleted on delivery; after 3 failures kept as `failed` (newest 1,000) | Deleted with the share; erasure |
| Other outgoing emails (verification, reset, invitation, share created, expiry warning, security notices) | Recipient | Service and security notifications | C / LI | In-memory queue only (not persisted) | Until sent | — |
| `audit_log`: `actor_id`, `actor_name`, `actor_role`, `target` (may contain `user#N (username)`), `detail` (may contain an administrator-typed disable reason, provider names, non-secret setting values), `ip` (**only while `audit_log_ip` is on**), `ts` | Actors and target users | Security, accountability, evidence | LI (and legal obligations of the controller, if any) | Yes (DB) | **`audit_retention_days`: 90 (default) to 365 days** | Removed by retention only. **Not rewritten on erasure** (see section 4) |
| `ip_bans`: client address (IPv6 per /64), ban end, strikes | Clients with repeated failed sign-ins | Brute-force protection | LI | Yes | Until the ban ended and 24 h passed without a new strike | Maintenance job; administrator can lift a ban |
| In-memory rate-limit and ban counters | Clients | Brute-force protection | LI | Memory only | Minutes; lost on restart | — |
| Database backups | All of the above | Recovery | LI | SQLCipher | The newest **`backup_keep` (default 7)** backups named `sendora-encrypted-*` (automatic daily ones and those an administrator makes) are kept, older ones are pruned after each automatic backup; pre-import backups (`sendora-preimport-*`) are never pruned automatically | Administrator deletes backups; data erased in the live database remains in older backups until they are removed |
| Forwarded audit records | As `audit_log` | Off-host evidence | LI | Receiver's responsibility | Receiver's retention | Receiver's process |

Not stored: raw IP addresses when `audit_log_ip` is off (the default), HTTP access logs, the user agent outside the session list, recipients' identities (recipients have no account), file contents in the audit log.

## 3. Short-lived plain data on disk

| Data | Removed |
|---|---|
| Upload parts (`uploads/<session>/<index>.part`) | On completion or abort; stale sessions after 24 h |
| Verified-download snapshots | After the transfer; leftovers at every start |
| Share directories being deleted (`shares/.deleting-*`) | After the deletion commit; leftovers at start |

## 3a. Multi-tenant mode: platform as processor

In multi-tenant mode each tenant is the controller of the personal data in its own database and directory (the inventory above applies per tenant). The platform operator processes that data on the tenant's behalf (processor, GDPR art. 28) and needs a data processing agreement with each tenant. The platform itself stores only:

| Data | Where | Purpose | Retention |
|---|---|---|---|
| Platform administrators: username, email, bcrypt hash, TOTP secret, sessions | `platform.db` | console access | until removed |
| Tenant name, subdomain, custom domains, quotas, counts of users and stored bytes | `platform.db` | operating the platform | until the tenant is deleted |
| Email address of the first tenant administrator | the tenant's database (not the platform's) and the platform audit log entry of the creation (username only) | first sign-in | tenant retention / platform audit retention |
| Platform audit log (actor, action, target, client IP) | `platform.db` | accountability of platform administrators | `platform_audit_retention_days` (default 365) |

Deleting a tenant removes its database, files and backups at once, everything under its prefix in the platform bucket, and Sendora's objects (`files/`, `backups/`, `probe/`) in storage the tenant configured itself (with the tenant's own credentials; refused when objects cannot be removed unless the platform administrator forces it, which lists what was left in the audit record). Copies kept by provider versioning or soft delete remain until their retention ends. Platform administrators cannot read tenant users or shares through the console, and see only the kind and usage of a tenant's own storage.

## 4. Data-subject rights

| Right | Support in Sendora | Notes |
|---|---|---|
| Access / portability (art. 15, 20) | **Profile → Your data**: `GET /api/users/me/export`, JSON (`sendora-personal-data-1`) with profile, settings, MFA overview (no secrets), linked logins, shares and file list (no contents), download history (no addresses), invitations, sessions (times only), and the user's own audit records (up to 100,000). Recorded as `personal_data_exported` before it is served | Not included: file contents (the user can download their own shares), session user agents and addresses, audit records in which the user is only the target, data in backups or forwarded logs. Guests cannot export |
| Rectification (art. 16) | Users change name, email (re-verification), languages and password in the profile; administrators can change name and email | — |
| Erasure (art. 17) | **Self-service** (`POST /api/users/me/erase`, password or recent sign-in) and **administrator erasure** (`POST /api/users/{id}/erase`, step-up). Deletes shares and files, upload sessions, invitations and their guest accounts, sessions, reset/verification codes, second factors, linked sign-ins, sign-in fingerprints and the password history, and pseudonymises the account row | The last administrator cannot be erased. See exceptions below |
| Restriction / objection | Administrators can disable an account (sessions, uploads and invitations revoked); not a formal restriction workflow | Process at the controller |
| Notification of recipients (art. 19) | Not provided | Controller's process |

**Exceptions to erasure (by design):**

- **Audit records** written while the account existed keep `actor_name` (the former username) and target labels such as `user#N (name)`. They are not rewritten because the audit log is a tamper-evident hash chain kept for the security of the service and the accountability of administrators (legitimate interest, art. 6(1)(f); art. 17(3)(e) for legal claims). They disappear with normal retention (at most 365 days). The same applies to copies already forwarded to stdout, syslog or a webhook.
- **Backups** made before the erasure contain the account until rotated out (`backup_keep`) or deleted by an administrator.
- **Account lifecycle fields** (`created_by`, `role_changed_by`, `email_changed_by`, `disabled_by`, `disabled_reason`) of the erased row and references to the erased person in other accounts' `*_by` fields are not cleared.
- Shares uploaded **by a guest** into the erased user's invitation are deleted with the account; shares the erased user received are not affected (recipients have no account).

There is **no legal hold**: retention jobs and erasure run regardless of any pending legal matter. A controller that needs a hold must take it outside Sendora (for example by preserving backups and forwarded logs).

## 5. Controller checklist

- Decide whether `audit_log_ip` is needed (it also controls session and download addresses) and document the choice.
- Set `audit_retention_days`, `clean_files_days`, `backup_keep` and the retention of forwarded logs and volume backups in line with your retention policy.
- Publish a privacy notice and set `privacy_url`; optionally `terms_url`, `terms_version` and `terms_acceptance_required`.
- Have a process for requests that Sendora does not cover (backups, forwarded logs, proxy logs, restriction).
- Treat the reverse-proxy logs as personal data: they contain client addresses and share URLs (link IDs are access credentials).
