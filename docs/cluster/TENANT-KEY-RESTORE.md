# Restoring a tenant-managed tenant

Applies to the Cluster flavour. A tenant is **platform-managed** by default: the operator
restores it with the platform's own KEK and needs nothing from the tenant. A tenant that uploaded its own
key is **tenant-managed**: the operator can restore the encrypted database, but only the tenant can make
it readable again. This page says what each side does.

## What the tenant must keep

- Its **KEK** (the key it uploaded), or the Shamir shares it was given (3 of 5) when the key was created.
  Store the shares with different people and in different places.
- The **KEK fingerprint** shown in the tenant admin UI, to check the right key is used.

The platform keeps no copy. Without the KEK, the data cannot be read by anyone: not by the tenant, not by
the operator, not from a backup. (Scope: encrypted database columns, blind indexes, settings secrets, audit text,
share-file content and the audit chain's MAC key: files and the chain come from the tenant's own `files` and
`audit-mac` keys, see [ENCRYPTION.md](../ENCRYPTION.md).)

Create a key with `sendora-db kek-generate` (add `-shares 3-of-5` for Shamir shares). It prints the key
(base64 of 32 random bytes) and its fingerprint; the same fingerprint is shown by `GET /api/admin/kek`.

## What is restored from backup (operator)

The operator restores the tenant database from a PostgreSQL backup (Barman or a volume snapshot) like any
tenant. That brings back: the encrypted columns, the control log and the **wrapped** data keys
(`tenant_keyring`), and the files (which are encrypted with keys wrapped the same way). The restored tenant
starts in state `locked`: the key endpoint answers 423 for it, every request to the tenant answers 423
(API: `{"code":"tenant_locked"}`; pages: an unlock page), and only the unlock endpoint works. The same happens
to every tenant-managed tenant after a controller restart (the key lives in controller memory only).

**After a master key rotation:** a backup holds the wraps and the control log as they were when it was
taken, so restoring it needs the master key version it was taken under (the platform record you restore with it
names that version; `master-<n>` must still be in the controllers' Secret). A tenant-managed tenant's data keys are
wrapped under its own key and are not touched by a master rotation, but its log's MAC KEK is a platform KEK of
that version too. Do not retire or remove a master version until every backup that needs it has expired and a newer
backup of every tenant exists. After restoring an older backup of a tenant whose record is on a newer version, restore
the platform record from the same time (or set it back), or run the master rotation again so the tenant is moved
forward.

## Tenant restore procedure

1. The operator restores the database and files (backup tooling) and tells the tenant it is `locked`.
   The tenant's platform record (mode `tenant` and the key fingerprint) lives in the platform database:
   restore that too, or re-create the tenant with the same id before restoring its database.
2. The tenant **presents the KEK**, by either:
   - `POST /api/unlock {"kek": "<base64>"}` on the tenant's own address (public endpoint, rate limited:
     10 attempts per address and 30 per tenant per 10 minutes; `GET /api/unlock` shows the expected
     fingerprint), or the unlock page that every request to the locked tenant shows; or
   - the operator on the tenant's behalf, inside a web pod:
     `sendora-db tenant-unlock -tenant <tenant id> -kek-file <file>` or
     `-shares <share1>,<share2>,<share3>` (the shares are combined in memory; `shamir-combine` is only
     needed to make a key file). The command reads `SENDORA_KEY_URL`, `SENDORA_KEY_CA` and
     `SENDORA_KEY_TOKEN_FILE` from the pod's environment.
   The key travels over TLS 1.3 to **every** controller replica and is held in their memory only; it is
   never written to disk or to a database. The call fails unless all controllers acknowledged; a controller
   that missed it stays locked for the tenant, so repeat the unlock.
3. Each controller checks the control log chain, that the key matches the recorded fingerprint and that
   every data key in the keyring unwraps with it. If any check fails, the tenant stays locked and the failed
   attempt is recorded in the platform audit log (`tenant_unlock`, outcome `failed`, fingerprint of the
   presented key; wrong key, or a log that was changed).
4. On success the controller holds the tenant's wrapping key, web replicas obtain it with their derived keys
   (cache lifetime `SENDORA_KEY_TTL_SECONDS`) and the tenant serves again. The unlock is recorded in the
   platform audit log and in the tenant's audit log (`kek_unlocked`).
5. After a restore to a **different cluster**, the same procedure applies; the tenant keys do not depend on
   the cluster (the platform record and the master key of the new cluster are needed for the platform side).

## If the key is lost

The tenant is unrecoverable. Restoring more backups does not help: every backup holds only wrapped keys.
The tenant can still be deleted. This is by design (crypto-shredding), and the UI asks for an explicit
confirmation before a tenant-supplied key replaces the platform-managed one.

## Rotating or replacing the key

Replacing the KEK is a rewrap of the data keys, not a re-encryption of the data:
`POST /api/admin/kek/replace {"old_kek": ..., "new_kek": ...}` (administrator, step-up). To go back to a
platform-managed tenant: `POST /api/admin/kek/release {"kek": ...}` (the data keys are wrapped under the
platform's KEK again and the tenant's wraps are destroyed). Switching a platform-managed tenant uses
`POST /api/admin/kek/upload {"kek": ..., "confirm": "<tenant slug>"}`. Each of these is a resumable hand-over:
if it was interrupted, repeat the same call with the same key(s). Keep the old key until the next backup that contains the rewrapped
keyring exists: an older backup still needs the old key.

## Test your restore

Do the following once after switching to a tenant-supplied key, and after every rotation: restore the latest backup to a scratch
database, start it locked, present the KEK, and check that known data reads back. A key that was never
tested is not a backup. The test suite does this on every build: `TestRestoredTenantStartsLockedAndUnlocksWithTheKEK`
(`internal/keyserver`) copies a tenant-managed tenant's database into a scratch database, shows it locked, refuses
a wrong key and unlocks it with the right one.
