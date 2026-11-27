# Contributing

Thanks for helping. Please read this first; it is short.

## Setup

```sh
git clone https://github.com/sendora-app/sendora.git
cd sendora
```

Requirements: Go (see `go.mod`), Node 26, and an official **SQLCipher 4.20.0** with
`pkg-config` (the Docker build compiles it; see the `Dockerfile`). The
[build guide](https://github.com/sendora-app/sendora/wiki/Installation-From-Source) has the commands. In short:

```sh
export CGO_ENABLED=1
npm --prefix web ci
npm --prefix web run build      # the Go binary embeds web/dist
go build -trimpath -o sendora .
```

## Tests

```sh
node --test web/src/*.test.mjs    # frontend logic and translations
go vet ./...
go test -race -timeout 40m ./...        # the app package takes several minutes
```

Please add or update a test with every behaviour change, especially anything
touching authentication, shares, uploads, quotas, or the database.

## Rules of the project

- **Security first.** No new network calls to third parties, no logging of
  secrets, addresses or tokens, additive database migrations only.
- **Never open the database while another query or transaction is open**; the
  store uses one pooled connection.
- **Translations:** English text is the key. Wrap user-visible text in `t('…')`,
  then run `node web/scripts/i18n-keys.mjs` to refresh `keys.json`. Dutch must stay
  complete (a test checks it); other languages may be partial. Example language
  files live in `custom-translations/`.
- Keep the documentation accurate: the [wiki](https://github.com/sendora-app/sendora/wiki) is the user documentation (and `docs/` holds the quick starts and the settings table).
- No personal data, real hostnames or credentials in code, tests or examples
  (use `example.com` and similar).

## Pull requests

Keep them focused, describe the problem and the fix, and make sure the tests above
pass.

`main` only changes through pull requests: the CI jobs `web`, `go`, `storage` and `image`
must pass on a branch that is up to date with `main`, review threads must be resolved, and
the history stays linear (squash or rebase; no force pushes). Release tags `v*` can only be
created by organisation administrators, and the release workflow waits for a maintainer's
approval in the `release` environment before it builds or publishes anything.

## License of contributions and sign-off

Sendora is licensed under `AGPL-3.0-or-later` with the additional terms in
[LICENSE-ADDITIONAL-TERMS.md](LICENSE-ADDITIONAL-TERMS.md) (see [NOTICE](NOTICE);
versions up to and including 0.2.0 were MIT). Contributions are accepted
**inbound = outbound**: you license your contribution under the same terms as the
project, `AGPL-3.0-or-later` **including the additional terms in
[LICENSE-ADDITIONAL-TERMS.md](LICENSE-ADDITIONAL-TERMS.md)** (the "Powered by
Sendora" attribution under section 7(b) and the trademark term under section 7(e)). There is **no CLA**; you keep the copyright in your
work, and nobody receives a right to relicense it on other terms.

Every commit must carry a **Developer Certificate of Origin** sign-off
([DCO 1.1](https://developercertificate.org/)). By adding it you certify that you
wrote the change, or otherwise have the right to submit it under the project's
license. Add it with `git commit -s`, which appends a line with your real name and
email:

```
Signed-off-by: Jane Doe <jane@example.com>
```

Forgot it? `git commit --amend -s` fixes the last commit, and
`git rebase --signoff main` fixes all commits of a branch. Pull requests without a
sign-off on every commit cannot be merged.

Do not submit code you copied from elsewhere unless its license is compatible with
`AGPL-3.0-or-later`, and say where it comes from in the pull request.
