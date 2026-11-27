# Sendora documentation

The complete documentation lives in the **[wiki](https://github.com/sendora-app/sendora/wiki)**. This folder keeps only:

- [Quick start: Docker](quickstart-docker.md) — one `docker run` command with the published image
- [Quick start: Kubernetes](quickstart-kubernetes.md) — bare-minimum manifest, port-forward, first administrator
- [Configuration settings](configuration.md) — every `SENDORA_*` variable and setting
- [Choosing a flavour](CHOOSING-A-FLAVOUR.md) — single-tenant, multi-tenant or Cluster; decision table; upgrading from 0.2
- [Helm chart](helm.md) — install any flavour with `deploy/helm/sendora`: prerequisites, values, upgrade, static checks
- [Cluster quickstart](cluster/QUICKSTART.md) — the Cluster flavour (preview): PostgreSQL, controller and web Deployments, first tenant, upgrades
- [Encryption](ENCRYPTION.md) — what is encrypted, the key hierarchy, rotation, tenant-managed keys, limits and a compromise table
- [Capability matrix](CAPABILITIES.md) — which features each flavour offers (generated)
- [Multi-tenancy](MULTI-TENANT.md) — optional: many organisations in one process (architecture, key derivation, routing, migration, limits)
- [Object storage](STORAGE.md) — S3, Azure Blob and Google Cloud Storage backends, credentials, migration, what the provider can see
- [Threat model](THREAT-MODEL.md) and [file format](FILE-FORMAT.md) — security design and the encrypted file specification
- [Compliance and audit documentation](compliance/README.md) — security whitepaper, shared responsibility matrix, data flows, personal data, audit events, vulnerability management
- [Screenshots](SCREENSHOTS.md) — the interface of 0.3 (the PNG files in `screenshots/` belong to the 0.2 wiki pages)

Main wiki pages: [Installation: Docker Compose](https://github.com/sendora-app/sendora/wiki/Installation-Docker-Compose) · [Docker deployment](https://github.com/sendora-app/sendora/wiki/Docker-Deployment) · [Kubernetes deployment](https://github.com/sendora-app/sendora/wiki/Kubernetes-Deployment) · [Installation: From source](https://github.com/sendora-app/sendora/wiki/Installation-From-Source) · [Configuration](https://github.com/sendora-app/sendora/wiki/Configuration) · [Hardening guide](https://github.com/sendora-app/sendora/wiki/Hardening-Guide) · [Accounts and authentication](https://github.com/sendora-app/sendora/wiki/Accounts-and-Authentication) · [Sharing and transfers](https://github.com/sendora-app/sendora/wiki/Sharing-and-Transfers) · [Email and notifications](https://github.com/sendora-app/sendora/wiki/Email-and-Notifications) · [Translations](https://github.com/sendora-app/sendora/wiki/Translations) · [Upgrades and backups](https://github.com/sendora-app/sendora/wiki/Upgrades-and-Backups) · [Security notes](https://github.com/sendora-app/sendora/wiki/Security-Notes) · [Troubleshooting](https://github.com/sendora-app/sendora/wiki/Troubleshooting) · [FAQ](https://github.com/sendora-app/sendora/wiki/FAQ)
