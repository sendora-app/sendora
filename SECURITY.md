# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for a security problem. Use GitHub's
private vulnerability reporting for this repository (Security tab → *Report a
vulnerability*). Include the version or commit, how to reproduce the problem, and
what an attacker gains. Do not include real user data or credentials.

Please allow reasonable time for a fix before you disclose the problem publicly.

### Response goals

Sendora is a volunteer project without a security team or paid support, so these
are goals, not guarantees:

- Acknowledge your report within **5 working days**.
- Give a first assessment or status update within **14 days**.
- For critical issues, aim for a fix or a documented mitigation within **30 days**.

If a goal cannot be met, you will hear why, and you are welcome to ask for an update.

## Supported versions

Only the latest release (or the `main` branch) receives security fixes.

## Scope

In scope: the Go server, the web interface, authentication (passwords, MFA, OIDC),
sessions, shares and uploads, the database encryption handling, the import and
backup tooling, and the container image and example manifests.

Out of scope: problems that need an already compromised server, administrator
account or database key; denial of service through unlimited traffic (put a proxy
in front, see `SENDORA_TRUSTED_PROXIES` in [Configuration](https://github.com/sendora-app/sendora/wiki/Configuration)); social engineering;
missing hardening of your own deployment.

## Independent review

Sendora was written largely by an AI coding assistant for a maintainer who is not a software developer. It has automated tests but has **not** been audited by an independent security professional. Reviews and responsible disclosure are very welcome.

## Known trade-offs

These are documented, deliberate decisions, not undisclosed bugs (details in the
[Security notes](https://github.com/sendora-app/sendora/wiki/Security-Notes)):

- Anyone who knows a username can lock that account's password sign-in for 15
  minutes. Administrators can unlock it.
- Invite tokens are stored in the database in plain text.
- Outgoing OpenID Connect requests (discovery, keys, token exchange) are made to
  addresses an administrator configures. Since 0.1.5 they refuse loopback,
  link-local and cloud-metadata targets after DNS resolution; private (RFC 1918)
  networks stay reachable on purpose, for identity providers on the local network.
- Passkey support is verified against a software authenticator and test vectors,
  not against every real device. Keep a recovery code.

## Verifying release images

Release images (`ghcr.io/sendora-app/sendora`) are built by the
[release workflow](.github/workflows/release.yml) only after the full test suite
passed, signed keylessly with [cosign](https://docs.sigstore.dev/) and published
with GitHub build provenance and SBOM (SPDX) attestations. Verify by digest; take
the digest of a version from the package page or with
`docker buildx imagetools inspect ghcr.io/sendora-app/sendora:<version>`.

Signature (cosign 3 or newer):

```sh
cosign verify ghcr.io/sendora-app/sendora@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/sendora-app/sendora/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Build provenance and SBOM attestations (GitHub CLI):

```sh
gh attestation verify oci://ghcr.io/sendora-app/sendora:<version> -R sendora-app/sendora
gh attestation verify oci://ghcr.io/sendora-app/sendora:<version> -R sendora-app/sendora \
  --predicate-type https://spdx.dev/Document/v2.3
```

A successful check proves that the image was built from this repository's
release workflow for a version tag; it says nothing about whether the code is
free of vulnerabilities. In Kubernetes, pin the verified digest
(`image: ghcr.io/sendora-app/sendora:<version>@sha256:<digest>`).

Images up to and including 0.1.4 were published before signing was introduced
and have no signature or GitHub attestations.

## Secrets

The database key (`SENDORA_DB_KEY_FILE`) is the only secret that cannot be
regenerated: losing it makes the database and its backups unreadable. Keep a
separate, protected copy and never commit it.
