# SQLCipher linkage

Pinned upstream: github.com/mattn/go-sqlite3 v1.14.53.
Module checksum: h1:mnTM0owzUMrKuLo+0w51NUiB0ir2Fo7kFXlPt/l3BGs=
Upstream MIT license remains in LICENSE.

Sendora changes: link exclusively against pkg-config sqlcipher; disable the
bundled plain SQLite amalgamation; install the driver-instance CipherKey via
sqlite3_key before executing any database PRAGMA; reject libsqlite3 build tag.

Requires official SQLCipher 4.20.0 (SQLite 3.54.1) and CGO. Do not replace with
an old embedded SQLCipher driver. Rebase this narrow fork when upstream updates,
retain license notices, and rerun encryption/wrong-key/connection/backup tests.
No secrets are bundled in this directory.
