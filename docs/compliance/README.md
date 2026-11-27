# Compliance and audit documentation

This folder collects the documents an auditor, security officer or data-protection officer needs to assess Sendora and a deployment of it: what the application does to protect data, what the operator must do, which events are logged, which personal data is processed and how vulnerabilities are handled. Each document was written from the source code and states plainly what is not provided.

Applies to version 0.1.5.

> **Not independently audited.** Sendora has automated tests and has had code reviews, but it has **not** been audited by an independent security professional and has **not** been penetration tested. Nothing in this folder is a certification or an attestation report. See [SECURITY.md](../../SECURITY.md#independent-review).

## Documents

| Document | Use it for |
|---|---|
| [SECURITY-WHITEPAPER.md](SECURITY-WHITEPAPER.md) | One-document overview: architecture, trust boundaries, authentication, authorisation, cryptography, logging, data protection, secure development, known limitations |
| [SHARED-RESPONSIBILITY.md](SHARED-RESPONSIBILITY.md) | ISO/IEC 27001:2022 Annex A and SOC 2 matrix: application vs. operator, available evidence, gaps |
| [DATA-FLOW.md](DATA-FLOW.md) | Diagram and table of every data flow with protocol, encryption and authentication |
| [PERSONAL-DATA.md](PERSONAL-DATA.md) | Personal-data inventory with purpose, retention, deletion and data-subject rights |
| [AUDIT-EVENTS.md](AUDIT-EVENTS.md) | Complete catalogue of audit actions, generic rules, sampling, `chain_head` heartbeat |
| [VULNERABILITY-AND-DEPENDENCY-MANAGEMENT.md](VULNERABILITY-AND-DEPENDENCY-MANAGEMENT.md) | Scanning, Dependabot, supported versions, response goals, release signing, image verification |
| [../THREAT-MODEL.md](../THREAT-MODEL.md) | Assets, actors, trust boundaries, security properties with code and test references, residual risks |
| [../FILE-FORMAT.md](../FILE-FORMAT.md) | Normative specification of the encrypted file format and database encryption, with test vectors |

Related: [configuration.md](../configuration.md) (every setting, audit forwarding, readiness and metrics), [SECURITY.md](../../SECURITY.md) (reporting, verifying images), [CHANGELOG.md](../../CHANGELOG.md) (section 0.1.5), [deploy/compose/README.md](../../deploy/compose/README.md). Wiki: [Audit log](https://github.com/sendora-app/sendora/wiki/Audit-Log), [Encryption](https://github.com/sendora-app/sendora/wiki/Encryption), [Hardening guide](https://github.com/sendora-app/sendora/wiki/Hardening-Guide), [Upgrades and backups](https://github.com/sendora-app/sendora/wiki/Upgrades-and-Backups), [Security notes](https://github.com/sendora-app/sendora/wiki/Security-Notes). The repository documents are complete without the wiki.

## Suggested reading order for an audit

1. [SECURITY-WHITEPAPER.md](SECURITY-WHITEPAPER.md) and [THREAT-MODEL.md](../THREAT-MODEL.md) for the design.
2. [SHARED-RESPONSIBILITY.md](SHARED-RESPONSIBILITY.md) to split the controls between Sendora and the deployment.
3. [AUDIT-EVENTS.md](AUDIT-EVENTS.md) and [PERSONAL-DATA.md](PERSONAL-DATA.md) for logging and privacy.
4. Collect evidence from a running deployment: audit export with chain status (`sendora-db audit-verify`), access-review export, `sendora-db verify-files`, image signature and attestations.

## security.txt

Sendora does **not** serve `/.well-known/security.txt` (RFC 9116). An operator who wants one can serve it from the reverse proxy in front of Sendora. Point it at **your own** security contact for the deployment; vulnerabilities in the Sendora software itself can be reported upstream through GitHub private vulnerability reporting ([SECURITY.md](../../SECURITY.md)).

Example content (replace every value; `Expires` is required and must be less than a year ahead):

```text
Contact: mailto:security@example.com
Expires: 2027-06-30T00:00:00Z
Preferred-Languages: en
Canonical: https://files.example.com/.well-known/security.txt
Policy: https://example.com/security-policy
```

Example for Caddy (the compose files in `deploy/compose` use Caddy for HTTPS), placed inside the site block before the reverse proxy:

```caddy
handle /.well-known/security.txt {
	header Content-Type "text/plain; charset=utf-8"
	respond `Contact: mailto:security@example.com
Expires: 2027-06-30T00:00:00Z
Preferred-Languages: en
Canonical: https://files.example.com/.well-known/security.txt
`
}
```

With nginx, an equivalent `location = /.well-known/security.txt { default_type text/plain; alias /etc/nginx/security.txt; }` serves a file. Requests for this path that reach Sendora are answered by the single-page-app fallback, not with a security.txt.
