# Cluster quickstart (preview)

[Back to the documentation index](../README.md) · [Choosing a flavour](../CHOOSING-A-FLAVOUR.md) · [Encryption](../ENCRYPTION.md)

How to run the Cluster flavour: several `web` replicas and several `controller` replicas on Kubernetes,
with a PostgreSQL 18 cluster that **you** provide. The Cluster flavour is a **preview**
([CAPABILITIES.md](../CAPABILITIES.md)). The image `ghcr.io/sendora-app/sendora:0.3.0` runs all three flavours. The Helm chart in
[`deploy/helm/sendora`](../../deploy/helm/sendora) ([docs/helm.md](../helm.md)) installs the application; this page
describes the pieces and points to example manifests in [examples/](examples/). Keys and encryption are in
[ENCRYPTION.md](../ENCRYPTION.md).

Values "in the test setup" are those of the project's own test cluster (kind, one node); where this page says
**test setup only**, replace the item in a real deployment.

## 1. What runs

| Component | Replicas | Role |
|---|---|---|
| `sendora-web` (`SENDORA_ROLE=web`) | 2 or more | Serves tenants and the platform console. Connects to PostgreSQL only through the PgBouncer pooler. No master key, no provisioner credentials, no ServiceAccount token mounted by default |
| `sendora-controller` (`SENDORA_ROLE=controller`) | 2 or more (one leader at a time, chosen with a Kubernetes Lease) | Creates and migrates the platform and tenant databases, provisions and drops tenants, runs background jobs, holds the master key and serves the **key endpoint** on port 8443 |
| PostgreSQL 18 (CloudNativePG) | 3 instances | Not part of Sendora. You operate it |
| PgBouncer poolers | 2 or more | CloudNativePG `Pooler` resources, transaction mode |

Web replicas fetch the keys they need from the controller's key endpoint over TLS 1.3, proving who they are
with a projected ServiceAccount token that the controller checks with the Kubernetes TokenReview API.

## 2. Prerequisites

- Kubernetes with the CloudNativePG operator (design: 1.30.1 or newer, tested on 1.30.2). The Pod Security
  level `restricted` works; the test setup uses it.
- A wildcard DNS name and a wildcard TLS certificate for `*.<base domain>`, an ingress that passes the original
  `Host`, and `SENDORA_TRUSTED_PROXIES` set to the ingress addresses ([MULTI-TENANT.md](../MULTI-TENANT.md),
  [configuration](../configuration.md)). The test setup has none of this: it uses plain HTTP through
  `kubectl port-forward` and the base domain `sc.localhost:18080` (**test setup only**).
- A 32-byte master key file (`sendora-db keygen -key-file <path>`), kept with an offline recovery copy.
  Losing it makes every platform-managed tenant unrecoverable ([ENCRYPTION.md](../ENCRYPTION.md)).
- A volume for share files that every web and controller replica can mount (RWX), mounted at `DATA_DIR`,
  or the platform storage settings of [STORAGE.md](../STORAGE.md). The test setup uses a PersistentVolumeClaim named
  `sendora-files`; on kind it is `ReadWriteOnce` on local-path storage (**test setup only**: one node).

### 2.1 PostgreSQL

The essentials, as in [examples/postgresql-cluster.yaml](examples/postgresql-cluster.yaml):

- `instances: 3`, `enableSuperuserAccess: false`, `smartShutdownTimeout: 0`, `postgresql.synchronous` with
  `method: any`, `number: 1`, `dataDurability: required`, `ssl_min_protocol_version: TLSv1.3`,
  `password_encryption: scram-sha-256`.
- Two managed roles with passwords from Secrets:
  - `sendora_provisioner`: login, `createdb`, `createrole`, not superuser, not replication. Used by controllers only.
  - `sendora_monitor`: login, member of `pg_monitor`. Used by controllers only.
- One statement as break-glass, once: `GRANT SET ON PARAMETER temp_file_limit, work_mem TO sendora_provisioner WITH GRANT OPTION`
  (for example with `kubectl exec` into the primary and `psql`).
- Server certificate names that include the pooler Service names (`certificates.serverAltDNSNames`), so Sendora
  can connect with `sslmode=verify-full` through PgBouncer.
- `podSelectorRefs` named `sendora-poolers` that selects the pooler pods, and `pg_hba` rules in this order, ending
  in a reject so the CloudNativePG default rule is never reached:

  ```yaml
  pg_hba:
    - hostnossl all all all reject
    - hostssl all sendora_provisioner <pod CIDR> scram-sha-256
    - hostssl postgres sendora_monitor <pod CIDR> scram-sha-256
    - hostssl samerole all ${podselector:sendora-poolers} scram-sha-256
    - host all all all reject
  ```

- Two `Pooler` resources (`rw`, optionally `ro`), `poolMode: transaction`, `max_prepared_statements: "200"`,
  `client_tls_sslmode: require`: see [examples/postgresql-poolers.yaml](examples/postgresql-poolers.yaml).
- A NetworkPolicy in the PostgreSQL namespace that admits port 5432 only from the poolers, the controller pods and
  the CloudNativePG pods: a tested example is in section 4.5.
- Storage: encrypted local storage per node for production. NFS is for tests only: on NFS-backed storage a failover
  can stall writes for a long time while replicas catch up. The test setup uses
  `local-path` storage (**test setup only**).
- Encrypted, continuously archived backups (Barman Cloud plugin). Not covered by the examples.

Check the result with the self-test, run from a controller pod or any pod that can reach the services:
`sendora-db cluster-check -direct-host <rw service> -pooler-host <pooler rw service> -ca-file <ca.crt> -provisioner-secret <dir with username and password>`
(add `-monitor-secret`, `-pooler-ro-host`, `-poolers`, `-tenants` as needed; see `sendora-db cluster-check -h`).

## 3. Secrets and certificates

Create these in the Sendora namespace (the examples use `sendora-cluster`; the secret names below are those of the test setup):

| Secret | Contents | Mounted in |
|---|---|---|
| `sendora-c-key` | `master-1` (and later `master-2`, ...): the 32-byte master key, one file per version | **controller only**, at `/etc/sendora-key` (a directory; `SENDORA_DB_KEY_FILE` names it), mode `0400` |
| `sendora-c-provisioner` | `username`, `password` of `sendora_provisioner` | **controller only**, directory named by `SENDORA_PG_PROVISIONER_DIR` |
| `sendora-c-pg-ca` | `ca.crt`: the PostgreSQL server CA | both roles, `SENDORA_PG_CA_FILE` |
| `sendora-c-keys-tls` | `tls.crt`, `tls.key`: server certificate of the key endpoint | controller only |
| ConfigMap `sendora-c-keys-ca` | `ca.crt`: CA that signed the key endpoint certificate | web, `SENDORA_KEY_CA` |
| `sendora-c-setup` | `code`: one-time setup code of the first platform administrator | web, `SENDORA_PLATFORM_SETUP_CODE` |

Create secrets with `kubectl create secret ... --from-file` or server-side apply, not with client-side
`kubectl apply` of a manifest holding the value (it copies the value into an annotation). Log Secrets at
`Metadata` level in the Kubernetes audit policy, restrict `get secrets` and `pods/exec`, and encrypt etcd.

The certificate of the key endpoint must cover the Service names `sendora-controller-keys`,
`sendora-controller-keys.<namespace>`, `.svc` and `.svc.cluster.local`. Certificates are the operator's
responsibility (cert-manager, your own CA, any other tool); Sendora only reads the files you mount. The test setup
uses a throwaway CA and a 825-day certificate and discards the CA key (**test setup only**).

## 4. Kubernetes objects

ServiceAccounts and RBAC: [examples/sendora-rbac.yaml](examples/sendora-rbac.yaml). The Deployments and Services are
rendered by the Helm chart: `helm template sendora deploy/helm/sendora -f deploy/helm/sendora/values-cluster-example.yaml`
shows them ([helm.md](../helm.md)). Use the image `ghcr.io/sendora-app/sendora:0.3.0` (it has `sendora` as entrypoint,
runs as UID 10001 and contains SQLCipher).

### 4.1 ServiceAccounts and RBAC

- `sendora-web` ServiceAccount with `automountServiceAccountToken: false`. The web pod gets only the projected token below.
- `sendora-controller` ServiceAccount with a Role on `coordination.k8s.io` `leases` (`get`, `create`, `update`) in its
  namespace, and a ClusterRole `tokenreviews` `create` bound to it. Nothing else.

### 4.2 Controller Deployment

Two replicas, `SENDORA_FLAVOUR=cluster`, `SENDORA_ROLE=controller`. Environment of the test setup:

| Variable | Value in the test setup | Purpose |
|---|---|---|
| `SENDORA_PG_POOLER` | `sendora-pg-pooler-rw.sendora-postgresql:5432` | Pooler address |
| `SENDORA_PG_DIRECT` | `sendora-pg-rw.sendora-postgresql:5432` | Direct read-write service (controller only) |
| `SENDORA_PG_CA_FILE` | `/etc/pg-ca/ca.crt` | PostgreSQL CA |
| `SENDORA_PG_PROVISIONER_DIR` | `/etc/pg-prov` | Directory with `username` and `password` |
| `SENDORA_BASE_DOMAIN` | `sc.localhost:18080` | Base domain (use yours) |
| `SENDORA_DB_KEY_FILE` | `/etc/sendora-key/db.key` | Master key (controller only) |
| `SENDORA_KEY_ADDR` | `:8443` | Key endpoint listen address |
| `SENDORA_KEY_TLS_CERT`, `SENDORA_KEY_TLS_KEY` | `/etc/sendora-keys-tls/tls.crt`, `.../tls.key` | Key endpoint certificate |
| `SENDORA_POD_NAME` | from the downward API | Replica identity for the Lease |
| `DATA_DIR` | `/data` | Share files volume |
| `SENDORA_PLATFORM_MFA_REQUIRED` | `"false"` in the test setup | **Test setup only.** The default is `true`: platform administrators need an authenticator app |

The key endpoint accepts only `system:serviceaccount:<namespace>:sendora-web` unless `SENDORA_KEY_USER` says otherwise.
Other variables (`SENDORA_LEASE_NAME`, `SENDORA_LEASE_SECONDS`, `SENDORA_PG_POOLERS`, `SENDORA_PG_SSLMODE`, ...) are in
[configuration.md](../configuration.md#cluster-flavour-configuration-preview).
Do not set `SENDORA_DB_INITIALIZE`, and do not point `DATA_DIR` at a Community SQLite database.
Container: `readOnlyRootFilesystem`, drop all capabilities, `runAsNonRoot`, `seccompProfile: RuntimeDefault`, an
`emptyDir` on `/tmp`; readiness probe `GET /api/health` on port 8080; port 8443 named `keys`.

### 4.3 Web Deployment

Two or more replicas, `SENDORA_ROLE=web`. It must **not** have `SENDORA_DB_KEY_FILE`, `SENDORA_PG_DIRECT` or
`SENDORA_PG_PROVISIONER_DIR` (the start is refused). Additional or different variables:

| Variable | Value in the test setup | Purpose |
|---|---|---|
| `SENDORA_KEY_URL` | `https://sendora-controller-keys.sendora-cluster.svc:8443` | Key endpoint (the Service below) |
| `SENDORA_KEY_CA` | `/etc/sendora-keys-ca/ca.crt` | CA of the endpoint certificate |
| `SENDORA_KEY_TOKEN_FILE` | `/var/run/sendora-keys/token` | Projected token |
| `SENDORA_KEY_TTL_SECONDS` | `"20"` in the test setup | Key cache lifetime. Default 600. The test setup shortens it so a locked tenant shows within seconds ([ENCRYPTION.md](../ENCRYPTION.md#6-tenant-managed-kek-cluster-only)) |
| `SENDORA_PLATFORM_SETUP_CODE` | from Secret `sendora-c-setup` | Required on every web replica until the first platform administrator exists |
| `SENDORA_TRUSTED_PROXIES` | not in the test setup | Set it behind an ingress |

The token volume:

```yaml
volumes:
- name: keys-token
  projected:
    sources:
    - serviceAccountToken:
        audience: sendora-keys
        expirationSeconds: 600
        path: token
```

### 4.4 Services

- `sendora-web`: ClusterIP on port 8080 to the web pods; put your ingress in front of it.
- `sendora-controller-keys`: port 8443 to the controller pods, **headless** (`clusterIP: None`). A tenant's own key is presented
  to every controller, so web pods need the addresses of all of them. The `clusterIP` of a Service is immutable: delete and
  re-create it when you change an existing one.

### 4.5 NetworkPolicy (recommended, not applied)

Recommended, but not applied by Sendora or its manifests: whether NetworkPolicies work depends on your CNI. Cilium,
Calico, Antrea and others enforce them; on a CNI that does not (kindnet, plain Flannel, ...) Kubernetes accepts them
and silently ignores them, so check yours first (a probe pod in another namespace must not reach the key endpoint). They are yours to
apply ([what you provide yourself](#what-you-provide-yourself)). A tested starting point is in
[examples/networkpolicy.yaml](examples/networkpolicy.yaml), plain `networking.k8s.io/v1` objects:

- **Sendora namespace:** default deny, then DNS for every pod; web pods accept 8080 from the ingress controller only
  and connect to the poolers (5432) and the controllers' key endpoint (8443), never to the PostgreSQL instances or
  the Kubernetes API; controller pods accept 8443 from web pods only and connect to the poolers and instances
  (5432) and the Kubernetes API. Outbound HTTPS and SMTP (OIDC, object storage, mail) are commented out: add only
  what you use.
- **PostgreSQL namespace (ingress only):** instances accept 5432/8000 from each other, the CNPG join and recovery
  jobs and the CNPG operator, and 5432 from the poolers and the Sendora controllers; poolers accept 5432 from
  Sendora web and controller pods. Egress of the CNPG pods stays open (the instance manager needs the API).

Adapt the namespaces, the ingress controller's namespace and the API server address (a `/32` per endpoint, never
`0.0.0.0/0`, which would also open 443 to the internet). **On Cilium** an `ipBlock` does not match the Kubernetes
API server (it is the `kube-apiserver` entity): also apply
[examples/networkpolicy-cilium.yaml](examples/networkpolicy-cilium.yaml), or the controllers lose leader election
and TokenReview while their pods still report Ready.

Verified on kind with Cilium 1.20: 24 allowed and refused connections from probe pods with the web, controller,
no, foreign-namespace and ingress identities, the end-to-end tests, the cross-replica checks (22/22), the
tenant-supplied key under load, a leader kill and a CNPG failover all pass with the policies applied. Without them every probe
reaches the key endpoint and PostgreSQL from any namespace.

The Helm chart renders its own variant with `networkPolicy.enabled=true` ([helm.md](../helm.md#networkpolicy)); use
one of the two.

## 5. First start

1. Apply the namespace (with `pod-security.kubernetes.io/enforce=restricted`), RBAC, Secrets, ConfigMap and the Services.
2. Apply the controller Deployment first. The leader creates and migrates the platform database `sendora_platform`.
   Web replicas retry at start, so the order is not strict.
3. Apply the web Deployment. A web pod without a platform administrator and without a setup code stops with a message.
4. Reach the console at `https://admin.<base domain>`. Create the first platform administrator with the setup code
   (the console asks for it; the API is `POST /api/platform/setup`). Then sign in. With the default
   `SENDORA_PLATFORM_MFA_REQUIRED=true`, enrol an authenticator app. Later setup calls answer 403.
5. Create a tenant in the console (or `POST /api/platform/tenants` with `slug`, `name`, `admin_email`,
   `admin_username`, `max_users`, `max_storage_bytes`, `storage_offer`, `allow_own_storage`). The controller provisions the database (roles, schema, keys, control log). The answer carries a
   `setup_link`: its last path segment is the token with which the tenant's administrator sets a password at
   `https://<slug>.<base domain>`. The tenant is routable on every web replica within a few seconds.
6. Tenant administrators can then rotate keys and, if they want, upload their own key
   ([ENCRYPTION.md](../ENCRYPTION.md)). Platform administrators cannot read tenant content.

## 6. Upgrades and rollouts

- **Master key file layout:** `SENDORA_DB_KEY_FILE` may name one file (version 1) or a
  directory of `master-<n>` files. A cluster that mounted a single `db.key` keeps working unchanged; to prepare for
  rotation, add the same bytes as `master-1` to the Secret and point `SENDORA_DB_KEY_FILE` at the directory.
- **Rotating the master key (runbook).** 1. Make sure `master-1` exists and every backup of the key is current
  (keys: [ENCRYPTION.md](../ENCRYPTION.md)). 2. Generate `master-<n+1>` offline (`head -c 32 /dev/urandom`), back it up
  the same way as the first (escrow or Shamir, `sendora-db shamir-split`), and add it to the Secret with
  `kubectl patch secret sendora-c-key --type merge -p '{"data":{"master-2":"<base64>"}}'` (never `kubectl apply` of a
  manifest holding it). 3. Wait until **every** controller pod lists it (`kubectl exec <controller> -- ls /etc/sendora-key`; the
  kubelet needs a minute or two). 4. Platform console, **Key management → Master key → Rotate**, with the reason and
  your authenticator code. The leader moves the tenants one at a time (a controller restart or a leader change only
  pauses it; progress and the controller's last note are on the screen; the platform audit log has
  `master_tenant_moved` per tenant). Tenant-managed tenants need no key from you or them. 5. When the screen shows
  every tenant on the new version, **keep the old file**: backups made before the rotation need it. Retire a version
  (same screen) and remove its file from the Secret only after those backups have expired and a newer backup of every tenant
  exists. **Version 1 cannot be retired** in this build (it still derives the database passwords and the platform's
  own keys). **What to keep:** every master version that a backup still needs, plus a tenant-managed tenant's own key
  ([TENANT-KEY-RESTORE.md](TENANT-KEY-RESTORE.md)).
- **Forced tenant key rotation (after an incident):** platform console, **Key management**: *Rotate keys* per tenant or
  for all platform-managed tenants (data, index, secrets, files; step-up and a reason). A tenant that holds its own key
  is skipped in bulk and answers `locked` unless its key is unlocked on every controller.

- **Order (suggested, not tested as a procedure):** roll the controllers first, then the web replicas. The leader applies
  database migrations; web replicas retry until the controller serves the key endpoint. 
- **Tenant-managed tenants lock on every controller restart** and stay unavailable until their key is presented again
  (`POST /api/unlock`, or `sendora-db tenant-unlock` from a web pod). Announce controller rollouts to those tenants.
  Platform-managed tenants are not affected. Controller pods that are not ready are not asked to unlock; they stay locked
  until the next unlock.
- **Key endpoint certificate:** replacing it means updating the Secret and restarting the controllers (and the CA
  ConfigMap and web pods if the CA changes).
- **Never switch the PostgreSQL primary over** before comparing `pg_last_wal_receive_lsn()` and `pg_last_wal_replay_lsn()` on
  every replica: a switchover to a lagging replica stalls writes until it has caught up.
- **Headless Service:** re-create `sendora-controller-keys` once when an older namespace had a ClusterIP Service.
- Backups of tenant databases and restore of tenant-managed tenants: [TENANT-KEY-RESTORE.md](TENANT-KEY-RESTORE.md).
- **0.2 data does not move to Cluster.** Cluster starts empty ([CHOOSING-A-FLAVOUR.md](../CHOOSING-A-FLAVOUR.md)).

## 7. Known gaps

### What you provide yourself

Sendora is the application only. Everything around it is the operator's, and this guide only states what the
application expects:

| Component | What Sendora expects |
|---|---|
| PostgreSQL 18 | Roles, `pg_hba`, TLS 1.3, HA, backups and point-in-time recovery (for example CloudNativePG; the manifests in [examples/](examples/) are an example, not a supported package) |
| TLS certificates | A certificate and key for the key endpoint (Service names above) and for ingress; issue them with cert-manager or any other tool |
| DNS | A wildcard or per-tenant records for the base domain, kept up to date by you (external-dns or manual) |
| Ingress / load balancer | Routes tenant host names to the web Deployment; terminates or passes TLS |
| Network policies | Allow web and controller to PostgreSQL (poolers and direct), web to controller on 8443, DNS and the Kubernetes API for the controller; deny the rest. Tested example: section 4.5 |
| Storage | Encrypted volumes for PostgreSQL and the file store, if you want disk-level encryption as well |
| Secrets management | How the master key file, the database passwords and the TLS material reach the pods |

Not built or not verified:

- A `sendora-db` command for master key rotation (the platform console does it).
- Not planned: journal and WORM anchors (a future journal would be encrypted), external KMS or HSM.
- Tenant export and import between clusters.
- WebAuthn across replicas is covered by unit tests only (the test setup has no HTTPS origin).
- An independent security review has not happened.
