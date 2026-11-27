# Helm chart

Install Sendora 0.3 on Kubernetes with the chart in [`deploy/helm/sendora`](../deploy/helm/sendora).

[Back to the documentation index](README.md) · [Choosing a flavour](CHOOSING-A-FLAVOUR.md) · [Cluster quickstart](cluster/QUICKSTART.md)

The chart installs the **application only**, in one of three flavours (`flavour: single | multi | cluster`). It
never deploys PostgreSQL, certificates, DNS records, an ingress controller or storage classes: they are
prerequisites that you provide and operate. The chart consumes them through values and checks none of them at
install time (it only fails early when a required value is missing).

## 1. Prerequisites

All of this is provided and operated by you.

| Needed | single, multi | cluster |
|---|---|---|
| Kubernetes 1.27 or newer, Helm 3.14 or newer (tested with Helm 4) | yes | yes |
| Container image of Sendora 0.3 in a registry the cluster can pull from (section 2) | yes | yes |
| Storage | a StorageClass for one ReadWriteOnce volume | a ReadWriteMany volume for share files (`DATA_DIR`), or `persistence.existingClaim` |
| **PostgreSQL 18** (never deployed by this chart) | no | yes: HA, backups and point-in-time recovery, TLS 1.3, the roles and `pg_hba` rules of the [Cluster quickstart](cluster/QUICKSTART.md#2-prerequisites), a PgBouncer-style pooler endpoint in transaction mode, a provisioner role (`sendora_provisioner`) that may `CREATE DATABASE` and `CREATE ROLE`, and the one-off `GRANT SET ON PARAMETER temp_file_limit, work_mem TO sendora_provisioner WITH GRANT OPTION` |
| Master key (32 random bytes) in a Secret: `sendora-db keygen -key-file database.key` | yes | yes |
| Connection budget for key jobs | no | **bulk key rotation opens connections**: every running key job (`keys.jobConcurrency` per controller, times the controller replicas) re-encrypts rows through the pooler. Budget `max_connections` (and the pooler limits) for that on top of the steady load: default 3 jobs x 2 controllers = 6 extra |
| Secrets for PostgreSQL | no | the provisioner credentials (files `username`, `password`) and the CA certificate of the server |
| TLS certificates (cert-manager or other) | one certificate for the host | a wildcard certificate for `*.<baseDomain>`; the certificate of the key endpoint (section 5) unless you use the convenience generator |
| DNS (external-dns or other) | the host | `*.<baseDomain>` and `<baseDomain>` to the ingress |
| Ingress controller (or Gateway API) | optional | yes, it must pass the original `Host` header |
| Network-policy engine (Calico, Cilium, ...) | only for `networkPolicy.enabled` | only for `networkPolicy.enabled` |

### Master key and secrets

```sh
sendora-db keygen -key-file ./database.key     # or: head -c32 /dev/urandom > database.key
kubectl -n sendora create secret generic sendora-master-key --from-file=database.key=./database.key
```

For master key **rotation** (cluster, multi) keep the key as a directory of versions instead: the Secret holds
`master-1`, later `master-2`, ... and the whole Secret is mounted as a directory that `SENDORA_DB_KEY_FILE` names.
A single file still works and is version 1.

```sh
kubectl -n sendora create secret generic sendora-master-key --from-file=master-1=./database.key
# values: masterKey.existingSecret: sendora-master-key, masterKey.secretKey: master-1
```

`masterKey.mountAsDirectory` decides how the Secret is used: `null` (default) detects it (a `secretKey` of the
form `master-<n>` means directory), `true` forces the directory (whatever `secretKey` is), `false` mounts the single
file `secretKey` only. An existing install with `database.key` keeps working unchanged; to prepare it, add the same
bytes as `master-1` to the Secret and set `masterKey.secretKey: master-1`.

Keep an offline recovery copy: losing the key loses all data ([ENCRYPTION.md](ENCRYPTION.md)). The chart
references Secrets by name (`masterKey.existingSecret`, `setupCode.existingSecret`, the PostgreSQL secrets).
**No secret is read from values unless you opt in:**

- `masterKey.generate: true` makes the chart create a random key. It is then stored in the Helm release Secret
  as well, so everyone who can read release Secrets can read it. Use it for trials only. The Secret is kept on
  uninstall and reused on upgrade. In directory mode it creates `master-1`. Later versions you add (`master-2`, ...)
  are merged back on upgrade (lookup): the chart never regenerates or overwrites an existing key.
- `setupCode.value` puts the one-time setup code into values and the release Secret. The default
  (`setupCode.generate: true`) creates a random code in a Secret that you read once.
- `cluster.keyEndpoint.tls.generate: true` keeps the server key of the key endpoint in the release Secret.

`generate` options use `lookup`: they work with `helm install/upgrade`, not with tools that render offline
(Argo CD, `helm template | kubectl apply`). There, use `existingSecret`.

### Rotating the master key

Cluster and multi, the [QUICKSTART](cluster/QUICKSTART.md) runbook with the chart's objects:

1. Check that `master-1` exists in the Secret and that every backup of the key is current.
2. Generate `master-2` offline (`head -c 32 /dev/urandom > master-2`), back it up like the first (escrow or
   Shamir) and add it to the Secret, without putting it in values or a manifest:
   `kubectl -n sendora patch secret sendora-master-key --type merge -p "{\"data\":{\"master-2\":\"$(base64 < master-2)\"}}"`.
   (With `masterKey.generate` the chart keeps what you add, a `helm upgrade` does not touch `master-2`.)
3. Make the controllers read it: the kubelet refreshes the mounted directory within a minute or two; check with
   `kubectl -n sendora exec deploy/<fullname>-controller -- ls /etc/sendora-key` on **every** controller pod, then
   `kubectl -n sendora rollout restart deploy/<fullname>-controller` (the master key is read at start). Single/multi:
   restart `deploy/<fullname>`. Web pods never get the key: they need no restart for this.
4. Platform console, **Key management, Master key, Rotate** (reason and authenticator code). Tenants move one at a
   time; progress is on the screen.
5. Keep the old file: backups made before the rotation need it. Retire a version only once no tenant and no
   backup you still need uses it (console **Retire**), then remove it from the Secret and restart the controllers.

## 2. The image

The chart uses the release image `ghcr.io/sendora-app/sendora:0.3.0` (amd64 and arm64, signed, with provenance and
SBOM attestations; see [SECURITY.md](../SECURITY.md)). To run your own build instead:

```sh
docker build -t registry.example.com/sendora:0.3.0 .          # add --platform linux/arm64 as needed
docker push registry.example.com/sendora:0.3.0
```

Values: `image.repository`, `image.tag` (default `Chart.appVersion`, `0.3.0`), `image.digest` (wins over the
tag), `image.pullPolicy`, `image.pullSecrets`. Forks must set `SENDORA_SOURCE_URL` through `config:`
([configuration](configuration.md)).

## 3. Install

```sh
helm install sendora deploy/helm/sendora -n sendora --create-namespace -f my-values.yaml
```

Start from [`values-single-example.yaml`](../deploy/helm/sendora/values-single-example.yaml),
[`values-multi-example.yaml`](../deploy/helm/sendora/values-multi-example.yaml) or
[`values-cluster-example.yaml`](../deploy/helm/sendora/values-cluster-example.yaml). The notes printed after the
install show the setup code command, the URLs and what to verify. Label the namespace
`pod-security.kubernetes.io/enforce=restricted`: the pods meet it.

First steps: read the setup code (`kubectl get secret <release>-setup -o jsonpath='{.data.code}' | base64 -d`),
open the console (`https://admin.<baseDomain>` for multi and cluster, the host itself for single) and create the
first (platform) administrator. In multi and cluster, create tenants in the platform console. For single and
multi set `database.initialize=false` after the first start.

## 4. What it creates

| Flavour | Objects |
|---|---|
| single, multi | Deployment (1 replica, `Recreate`, SQLite on one volume), PVC, Service, ConfigMap, ServiceAccount (no token), optional Ingress, NetworkPolicy and PodDisruptionBudget, chart-created Secrets only on opt-in |
| cluster | Deployment `<fullname>-controller` (2, `SENDORA_ROLE=controller`, master key, provisioner credentials, PostgreSQL CA and key endpoint certificate mounted), Deployment `<fullname>-web` (2, `SENDORA_ROLE=web`, **no master key, no provisioner credentials**, a projected ServiceAccount token with audience `sendora-keys` for 600 s, the key endpoint CA, `automountServiceAccountToken: false`, `enableServiceLinks: false`), Service `<fullname>-web`, **headless** Service `<fullname>-controller-keys` (the key endpoint fan-out needs every controller pod), a shared PVC, ServiceAccounts, Role for Leases, ClusterRole and ClusterRoleBinding for TokenReview, two PodDisruptionBudgets, topology spread, optional Ingress and NetworkPolicies |

All pods follow the restricted Pod Security Standard: non-root (10001), all capabilities dropped, read-only root
filesystem with an `emptyDir` on `/tmp`, seccomp `RuntimeDefault`, no privilege escalation. Probes use
`/api/health`. Config changes (`config:`, computed environment) roll the pods through a checksum annotation. A
changed Secret that you manage is not noticed: `kubectl rollout restart`.

### Volume ownership

Sendora (UID 10001) restricts its data directory to mode 0700 and therefore must own the volume root. On storage
that hands out a root-owned volume (local-path, k3s, some NFS or CSI drivers) the pod stops with
`chmod /data: operation not permitted`. Preferred: the storage administrator fixes the ownership. Otherwise set
`volumePermissions.enabled: true`: a one-time root init container does the `chown` (capabilities `CHOWN` and
`FOWNER` only, by default the Sendora image itself). **A root container does not meet the `restricted` Pod
Security Standard**, so the namespace then needs `baseline`. In the cluster flavour it runs in the controller pods.

## 5. Cluster flavour

```yaml
flavour: cluster
baseDomain: sendora.example.com
masterKey:
  existingSecret: sendora-master-key
setupCode:
  existingSecret: sendora-setup
cluster:
  postgres:
    pooler: sendora-pg-pooler-rw.postgres.svc:5432
    direct: sendora-pg-rw.postgres.svc:5432
    caSecret:
      name: sendora-pg-ca
    provisionerSecret:
      name: sendora-pg-provisioner
  keyEndpoint:
    tls:
      existingSecret: sendora-keys-tls
```

`helm template` and `helm install` fail with a clear message, and `values.schema.json` rejects the values, when
`baseDomain`, `cluster.postgres.pooler`, `.direct`, `.provisionerSecret.name` or (unless `sslMode: require`)
`.caSecret.name` are missing. Use `cluster.postgres.platformDatabase` when two installs share one PostgreSQL.

### Key endpoint TLS

Web replicas fetch derived keys from the controllers over TLS 1.3 and prove who they are with the projected
token. Either:

- **production**: `cluster.keyEndpoint.tls.existingSecret` names a Secret with `tls.crt`, `tls.key` and the CA in
  `ca.crt` (a cert-manager `Certificate` produces exactly that). Required SANs, with `<svc>` =
  `<fullname>-controller-keys`: `<svc>`, `<svc>.<namespace>`, `<svc>.<namespace>.svc`,
  `<svc>.<namespace>.svc.cluster.local` (set `clusterDomain` if yours differs). Web pods mount only `ca.crt`; to
  keep them away from that Secret altogether publish the CA in a ConfigMap or Secret of its own and set
  `cluster.keyEndpoint.tls.caConfigMap` or `.caSecret`.
- **tests and small installs**: `cluster.keyEndpoint.tls.generate: true`. The chart generates a CA and a server
  certificate with these SANs (valid `validityDays`, default 10 years), keeps them across upgrades and puts the
  CA in ConfigMap `<fullname>-keys-ca`. The server key sits in Secret `<fullname>-keys-tls` and in the release
  Secret; the CA private key is discarded. To rotate, delete both objects, `helm upgrade`, restart the pods.

Controllers accept only the web ServiceAccount of this release (`cluster.keyEndpoint.user` overrides).

### Storage, scheduling, disruption

The volume (`persistence.*`) must be mountable by every web and controller pod: ReadWriteMany (the default access
mode of the cluster flavour), or `persistence.existingClaim`. Both Deployments spread over nodes
(`topologySpread`, soft by default) and use rolling updates with `maxUnavailable: 0`. PodDisruptionBudgets keep
one replica of each (`pdb.minAvailable`).

### NetworkPolicy

Off by default, and recommended when your CNI enforces NetworkPolicy (Cilium, Calico, Antrea, ...). The chart does not
turn it on for you: on a CNI without support Kubernetes accepts the objects and silently ignores them, and the
selectors depend on your cluster. With `networkPolicy.enabled: true` the chart renders: ingress controller to web (8080), web to
PostgreSQL pooler (`networkPolicy.postgres.port`, default 5432), web to controller key endpoint (8443),
controller to the PostgreSQL pooler and direct services, controller to the Kubernetes API (Leases, TokenReview),
DNS, and outbound HTTPS and SMTP (`internetEgress`). **The selectors are examples**: set
`networkPolicy.ingress.namespaceSelector` to your ingress controller's namespace, `networkPolicy.postgres.*` to the
PostgreSQL namespace and pods, and `networkPolicy.kubeApi.cidrs` to your API server address. Cilium's built-in
ingress needs a `CiliumNetworkPolicy` instead; use `extraIngress` and `extraEgress` for what is specific to your
cluster. The NetworkPolicy of single and multi allows only the ingress controller, DNS and outbound HTTPS/SMTP.

**Cilium:** the controllers' Kubernetes API rule is an `ipBlock`, and Cilium does not match the API server with an
`ipBlock` (it is the `kube-apiserver` entity). With `networkPolicy.enabled: true` alone the controllers cannot read
or renew their Lease and cannot call TokenReview: their pods report Ready, but no leader is elected and web pods
get no keys. Apply [cluster/examples/networkpolicy-cilium.yaml](cluster/examples/networkpolicy-cilium.yaml) in the
release namespace as well (it selects `app.kubernetes.io/component: controller`, which the chart's controller pods
carry). Tested on kind with Cilium 1.20. The chart does not cover the PostgreSQL side; see
[cluster/examples/networkpolicy.yaml](cluster/examples/networkpolicy.yaml) (section 5 and 6) for a starting point.

## 6. Values reference (main values)

| Value | Default | Meaning |
|---|---|---|
| `flavour` | `single` | `single`, `multi` or `cluster` |
| `image.repository`, `.tag`, `.digest`, `.pullPolicy`, `.pullSecrets` | `ghcr.io/sendora-app/sendora`, appVersion, -, `IfNotPresent`, `[]` | image |
| `baseDomain` | `""` | multi and cluster: tenants on `<slug>.<baseDomain>`, console on `admin.<baseDomain>` (may carry `:port` for tests) |
| `appUrl` | `""` | single: public URL (`APP_URL`) |
| `trustedProxies` | `""` | `SENDORA_TRUSTED_PROXIES`, set it behind an ingress |
| `config` | `{}` | further `SENDORA_*` settings, rendered into a ConfigMap and environment |
| `extraEnv`, `extraEnvFrom`, `extraVolumes`, `extraVolumeMounts` | empty | for example an SMTP password file from a Secret |
| `database.initialize` | `true` | single/multi `SENDORA_DB_INITIALIZE`; set `false` after the first start |
| `masterKey.existingSecret`, `.secretKey`, `.generate` | `""`, `database.key`, `false` | master key Secret (section 1) |
| `setupCode.existingSecret`, `.secretKey`, `.value`, `.generate` | `""`, `code`, `""`, `true` | first-administrator code |
| `persistence.enabled`, `.existingClaim`, `.storageClass`, `.accessModes`, `.size`, `.keep` | on, `""`, `""`, RWO (RWX for cluster), `10Gi`, `true` | data volume; `keep` keeps the PVC on uninstall |
| `volumePermissions.enabled`, `.image` | off | root init container that chowns the volume (section 4) |
| `app.resources`, `app.pdb.enabled`, `app.probes` | 250m/512Mi, 2Gi limit; PDB off | single/multi Pod |
| `service.type`, `.port` | `ClusterIP`, `80` | Service |
| `ingress.enabled`, `.className`, `.annotations`, `.hosts`, `.tls.secretName` | off | host list defaults to `*.<baseDomain>` and `<baseDomain>` (multi, cluster); required for single |
| `networkPolicy.*` | off | section 5 |
| `cluster.postgres.pooler`, `.direct`, `.sslMode`, `.platformDatabase`, `.poolers`, `.caSecret`, `.provisionerSecret` | required values, `verify-full`, `sendora_platform`, `2` | PostgreSQL connection (prerequisite) |
| `cluster.platformMfaRequired` | `true` | platform administrators need an authenticator app |
| `masterKey.mountAsDirectory` | `null` (detect) | directory of `master-<n>` files or single file (section 1) |
| `keys.jobConcurrency` | `3` (1-64) | `SENDORA_KEY_JOB_CONCURRENCY`: key jobs at once per controller (single/multi: the app) |
| `keys.opsPerHour` | `10` (1-10000) | `SENDORA_KEY_OPS_PER_HOUR`: key operations per hour per tenant and for the platform console |
| `cluster.keyEndpoint.*` | see section 5 | port, cache lifetime, allowed caller, TLS |
| `cluster.web.*`, `cluster.controller.*` | 2 replicas each | replicas, resources, scheduling, topology spread, PDB, rolling update, grace period |
| `podSecurityContext`, `containerSecurityContext` | restricted | override only to relax deliberately |
| `serviceAccount.*`, `nameOverride`, `fullnameOverride`, `clusterDomain` | | naming |

`helm show values deploy/helm/sendora` has every value with comments.

## 7. Upgrade, rollback, uninstall

```sh
helm upgrade sendora deploy/helm/sendora -n sendora -f my-values.yaml
helm rollback sendora <revision> -n sendora
```

Back up first (section 8) and read the changelog before every upgrade. single
and multi use `Recreate`, so an upgrade has a short downtime. Cluster rolls both Deployments without downtime;
controllers re-lock tenant-managed tenants on restart ([ENCRYPTION.md](ENCRYPTION.md#6-tenant-managed-kek-cluster-only)). Do not scale the single
and multi Deployment above one replica.

`helm uninstall` removes the workloads, Services, ConfigMap, RBAC and the chart-created setup-code and generated
key endpoint Secrets. It
**keeps** the data PVC (`persistence.keep`), a chart-generated master key Secret and Secrets and databases you
created yourself (PostgreSQL is never touched). Delete them deliberately:
`kubectl delete pvc <fullname>-data`. Without the key the data is unrecoverable.

## 8. Backup notes

- The master key: offline copy, separate from data backups.
- single and multi: back up the volume (`/data`: `sendora.db`, `platform.db`, `tenants/`) with snapshots or
  `sendora-db backup`; see [ENCRYPTION.md](ENCRYPTION.md). Snapshot while the Pod is stopped or use the built-in
  backup.
- cluster: PostgreSQL backups and PITR (yours, see the prerequisites), the shared files volume, the master key and
  per-tenant key recovery ([TENANT-KEY-RESTORE.md](cluster/TENANT-KEY-RESTORE.md)).

## 9. Security notes

- Web pods hold neither the master key nor the provisioner credentials and have no automounted ServiceAccount
  token. The controller verifies the projected token through TokenReview (ClusterRole `tokenreviews: create`).
- Only the Secrets you reference are mounted; generated Secrets are opt-in and documented above.
- Pods are restricted-PSS compliant; a `NetworkPolicy` is recommended but opt-in because support and selectors depend on your CNI.
- The release Secret contains rendered values: use `existingSecret` for anything that matters.
- The chart creates a cluster-scoped ClusterRole and ClusterRoleBinding (TokenReview), named with the namespace,
  so two releases in different namespaces do not collide.

## 10. Static checks

`helm lint deploy/helm/sendora -f deploy/helm/sendora/values-<flavour>-example.yaml` and `helm template` with the
same values files check the chart without a cluster. The schema (`values.schema.json`) checks value types, and
the templates stop with a message on contradictory settings (an unknown flavour, a missing `baseDomain`, ...). On kind (one node, ReadWriteOnce local-path storage) set
`persistence.accessModes` to `ReadWriteOnce` (**test only**); the single flavour there also needs
`volumePermissions.enabled=true` (local-path hands out a root-owned volume) and a `baseline` namespace.

