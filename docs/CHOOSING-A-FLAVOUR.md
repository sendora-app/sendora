# Choosing a flavour

[Back to the documentation index](README.md)

One binary and one container image run as one of three flavours. `SENDORA_FLAVOUR` selects the flavour
([configuration](configuration.md#flavour)); without it the mode is detected from the data directory.

| Flavour | `SENDORA_FLAVOUR` | Database | Status |
|---|---|---|---|
| **Single-tenant** | `single` (default) | SQLite, encrypted with SQLCipher | Stable. Main path for a home or small-office setup, or one organisation |
| **Multi-tenant** | `multi` | One SQLCipher database per tenant plus a platform database | Stable. Main path for a small business or a host serving a few organisations |
| **Cluster** | `cluster` | PostgreSQL 18 on CloudNativePG, **supplied by you** | **Preview** (see [CAPABILITIES.md](CAPABILITIES.md)) |

Single-tenant and multi-tenant are the **Community** flavours: one process, one volume, no database
server to run. Cluster is for operators who already run Kubernetes and PostgreSQL and need several
replicas. Sendora does not install or operate PostgreSQL: the operator provides a CloudNativePG cluster
that meets the [prerequisites in the Cluster quickstart](cluster/QUICKSTART.md#2-prerequisites).

## Decision table

| | Single-tenant | Multi-tenant | Cluster |
|---|---|---|---|
| Who it is for | One person, family, team or company | An organisation hosting several others (departments, customers) | A platform operator with Kubernetes and PostgreSQL skills |
| Tenants | One | Many, each on its own subdomain or custom domain, managed in a platform console | Many, same console, one PostgreSQL database and set of roles per tenant |
| Scale | One process, one volume | One process (tenants opened on demand, limit `SENDORA_MAX_OPEN_TENANTS`) | Several `web` replicas and several `controller` replicas |
| Operations effort | Lowest: one container, one key file, one volume | Low: adds wildcard DNS and TLS | Highest: Kubernetes, CloudNativePG, poolers, TLS for the key endpoint, backups, upgrades of two Deployments |
| High availability | No. A restart means a short outage | No. Same | Yes for the application (replicas, leader election with a Kubernetes Lease). Database HA comes from CloudNativePG (3 instances, quorum replication, see the design) |
| Database | SQLCipher file | SQLCipher file per tenant | PostgreSQL 18 through PgBouncer |
| Whole-database encryption | Yes (SQLCipher, external key file) | Yes | No. PostgreSQL has none. Use encrypted volumes and backups |
| Column encryption, blind indexes, control log | Yes | Yes | Yes |
| Tenant key rotation (data, index, secrets, audit-enc, files) | Yes, by the administrator | Yes, by each tenant's administrator | Yes, by each tenant's administrator |
| Tenant-managed key (upload your own KEK) | No | No | Yes |
| Master key kept out of the internet-facing pods | Not applicable (one process holds it) | Not applicable | Yes: only `controller` pods mount it |
| Convert between flavours | Single to multi: Admin → Multi-tenant or `sendora-db tenant-import` | | No migration from the SQLite flavours (below) |
| Share files on a volume | Local data directory | Local data directory | A volume every replica can mount (RWX, for example NFS or CephFS) |
| Object storage (S3, Azure, GCS) | Yes ([STORAGE.md](STORAGE.md)) | Yes | Listed as available in [CAPABILITIES.md](CAPABILITIES.md); not yet tested in a Cluster deployment |
| Documentation | [Quick start: Docker](quickstart-docker.md), [Kubernetes](quickstart-kubernetes.md), [Helm chart](helm.md) | [MULTI-TENANT.md](MULTI-TENANT.md) | [cluster/QUICKSTART.md](cluster/QUICKSTART.md) |

Rule of thumb: start with single-tenant. Move to multi-tenant when you need separate organisations.
Choose Cluster only when you need more than one application replica and can operate PostgreSQL.
What each encryption layer protects, and what it does not, is in [ENCRYPTION.md](ENCRYPTION.md).

## No migration from the SQLite flavours to Cluster

Cluster starts empty on PostgreSQL. There is no converter from a SQLite
installation, single or multi-tenant, to Cluster, and none is planned. Plan the choice before you collect data.

Moving **one tenant between clusters** by export and import is **not built**: tenant data does not move
between clusters.

The path that does exist is inside the SQLite flavours: a single-tenant installation becomes a tenant of a
multi-tenant platform, in place (Admin → Multi-tenant) or with `sendora-db tenant-import`
([MULTI-TENANT.md](MULTI-TENANT.md)).

## Upgrading from 0.2 to 0.3

What changes for an existing 0.2 installation of a SQLite flavour:

1. **Back up first**, and keep the key file. Stop the application for the offline steps below.
2. **Detection is unchanged.** Without `SENDORA_FLAVOUR`, 0.3 starts in the mode 0.2 used.
3. **New databases are encrypted per column from their first start.** A fresh single-tenant database, and
   every tenant created by 0.3, gets its own control log and keys at first start and verifies them at every
   start. If the log or the keys do not verify, the database is not opened.
4. **A 0.2 database is refused** until it is converted, with a message naming the command. Convert it
   offline; the tool first writes a safety copy next to the database
   (`<database>.pre-column-encryption-<timestamp>`) and then encrypts the plaintext values in place:

   ```sh
   # single-tenant
   sendora-db upgrade-encryption -source /data/sendora.db -data-dir /data -key-file /run/secrets/database.key
   # multi-tenant: the platform database once, then every tenant (the directories in /data/tenants),
   # all with the master key
   sendora-db upgrade-encryption -platform -data-dir /data -key-file /run/secrets/database.key
   sendora-db upgrade-encryption -source /data/tenants/<id>/sendora.db -data-dir /data/tenants/<id> \
     -key-file /run/secrets/database.key -tenant <id>
   ```

   For a tenant that was imported from a single-tenant installation and still uses that installation's key for
   files and audit chain, add `-legacy-root` (and `-source-key-file` if its old key differs from the master
   key). Check the installation, then delete the safety copies.
5. **Stored files written by 0.2 are refused** (HTTP 503) until they are re-encrypted under the tenant's
   `files` key. Run `sendora-db files-reencrypt` offline (back up the data directory too), or call
   `POST /api/admin/keys/reencrypt-files` as an administrator (needs step-up).
   `GET /api/admin/keys` shows `legacy_files`, the number still waiting.
6. **The audit chain of 0.2 is not converted.** Its records were authenticated with a key derived from the
   old root, so verification reports the chain as broken from its first record. The records themselves stay.
   (See the changelog: "start a new database" is the supported route when an unbroken chain matters.)
7. **Backups made before the upgrade** are 0.2 databases and need the same conversion after a restore.
   Restoring a backup from another installation re-keys the column layer.
8. **Cluster is not an upgrade target.** It starts fresh, and `SENDORA_FLAVOUR=cluster` refuses a data directory
   that holds a Community SQLite database.

After the upgrade, tenant administrators can rotate keys ([ENCRYPTION.md](ENCRYPTION.md#rotating-keys)).
