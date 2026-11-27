# Quick start: Kubernetes (bare minimum)

The minimum to try Sendora in a cluster with [`deploy/kubernetes-minimal.yaml`](../deploy/kubernetes-minimal.yaml): a 2Gi volume, one pod and a service, reached through `kubectl port-forward`. For production (ConfigMap, Secrets, Ingress with HTTPS, hardened pod) follow the full [Kubernetes guide](https://github.com/sendora-app/sendora/wiki/Kubernetes-Deployment).

[Back to the documentation index](README.md)

Requirements: `kubectl` access to a cluster with a default StorageClass (any local cluster such as kind, minikube, k3s or Docker Desktop works) and `openssl` (on Windows use the PowerShell steps in section 1).

## 0. Storage

The manifest asks the cluster's **default StorageClass** for a 2Gi volume. Check that there is one:

```sh
kubectl get storageclass      # one class should show "(default)"
```

No default class? Either add `storageClassName: <name>` under the PVC's `spec:` in the manifest, or, for a test on one node, create a hostPath volume that the claim binds to:

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: sendora-test-pv
spec:
  capacity:
    storage: 2Gi
  accessModes:
    - "ReadWriteOnce"
  persistentVolumeReclaimPolicy: Retain
  claimRef:
    namespace: sendora
    name: sendora-data
  hostPath:
    path: /mnt/data/sendora
    type: DirectoryOrCreate
```

hostPath volumes live on one node and are meant for tests. On **Talos Linux** only `/var` is writable and `/var/mnt` is reserved for mounted disks: use a path such as `/var/local/sendora` there. With several nodes, add a `nodeAffinity` to the PV so the pod always lands on the node that holds the data. Neither hostPath nor most NFS provisioners enforce the size: to really limit storage, set the default storage quota under Admin → Settings (for example 2 GB).

## 1. Database key and Secret

```sh
(umask 077; set -C; openssl rand 32 > database.key)
kubectl create namespace sendora
kubectl -n sendora create secret generic sendora-db-key --from-file=database.key=./database.key
```

On **Windows (PowerShell)** there is no `openssl`, and in Windows PowerShell 5.1 the `>` redirect re-encodes the key (32 bytes became 72 in a test), so do not use `openssl rand 32 > database.key` there. Create the key with .NET instead. The key creation was tested in Windows PowerShell 5.1 and PowerShell 7.7 (the file is exactly 32 bytes); the `kubectl` commands are the same as above:

```powershell
$key = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($key); $rng.Dispose()
[System.IO.File]::WriteAllBytes("$PWD\database.key", $key)
kubectl create namespace sendora
kubectl -n sendora create secret generic sendora-db-key --from-file=database.key=./database.key
```

The key is exactly 32 random bytes and encrypts the database and the stored share files. **Keep a copy in a safe place**: without it the data cannot be read, and it cannot be regenerated.

## 2. Deploy

```sh
kubectl apply -f https://raw.githubusercontent.com/sendora-app/sendora/main/deploy/kubernetes-minimal.yaml
kubectl -n sendora rollout status deploy/sendora
```

(or `kubectl apply -f deploy/kubernetes-minimal.yaml` from a clone of the repository.)

## 3. Create the administrator

```sh
kubectl -n sendora logs deploy/sendora | grep "setup code"
kubectl -n sendora port-forward svc/sendora 8080:80
```

Open http://localhost:8080, enter the setup code and create the administrator account. The code is printed only while no account exists and changes on every pod restart: use the last line, from the log of the running pod (also when Argo CD or Flux deploys Sendora). More details: [First-run setup code](https://github.com/sendora-app/sendora/wiki/Accounts-and-Authentication#first-run-setup-code).

## 4. After the first start

Database creation should only be allowed for the very first start, so a lost volume is never silently replaced by an empty database:

```sh
kubectl -n sendora set env deploy/sendora SENDORA_DB_INITIALIZE=false
```

## Remove it again

```sh
kubectl delete namespace sendora
```

This deletes the volume and all data (depending on your StorageClass reclaim policy).

## Next steps

The minimal manifest runs an init container as root once to give the volume to the app user, leaves `APP_URL` unset so any local port-forward address works (set it to your public https:// address when you add an Ingress), and has no HTTPS, mail or sign-in providers configured. Because of that init container it meets the Pod Security Standard *baseline*, not *restricted*; the app container itself runs without root, with a read-only root filesystem and CPU/memory limits (1 CPU, 1 GiB).

Moving on to a real deployment: [Kubernetes guide](https://github.com/sendora-app/sendora/wiki/Kubernetes-Deployment) and the full manifest [`deploy/kubernetes.yaml`](../deploy/kubernetes.yaml). It enforces Pod Security *restricted* on the namespace, uses its own ServiceAccount without an API token, and leaves network policies to you: [`deploy/networkpolicy.yaml`](../deploy/networkpolicy.yaml) is the recommended set (only the ingress controller in; DNS, HTTPS to sign-in providers and SMTP out), not applied by the manifest because it only works on a CNI that enforces NetworkPolicy (Cilium, Calico, ...; on others it is silently ignored). Replace its ingress-controller namespace placeholder before applying it, and leave the storage ownership to the storage administrator (it has no root init container).
