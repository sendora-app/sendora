# Sendora stored-file format and database encryption

Status: normative for Sendora 0.1.5 and later (file format version 2). The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

Reference implementation: `internal/filecrypt`. Test vectors: `internal/filecrypt/testdata/vectors.json`, regenerated independently by `docs/tools/verify_vectors.py` (Python `cryptography` package). A change to this document, the code or the vectors that breaks one of the three is a bug.

## 1. Scope and threat model

This document defines how share files are stored on disk and how the SQLite database is encrypted. It protects data **at rest**:

- Someone who obtains a copy of the data volume, a backup or a disk image, but not the database key, learns neither file contents nor database contents.
- Someone who can write to the data volume but does not have the key cannot modify, truncate, reorder, extend, or substitute stored file contents without the change being detected on read. In format v2 this includes copying the ciphertext of one file over the ciphertext of another file (see 6.3).

It does **not** protect against: an attacker with the key; an attacker who controls the running process (memory, key file); traffic on the network (TLS is separate); whole-database rollback to an older consistent state (see 10).

## 2. Notation

- `||` is byte concatenation. `x[a:b]` is bytes a up to, not including, b.
- `u64be(n)` is n as 8 bytes, big endian. All sizes are in bytes.
- `HKDF(ikm, salt, info, L)` is HKDF (RFC 5869) with SHA-256, output length L. An absent salt (`nil`) is the RFC default: HashLen zero bytes.
- `AES-256-GCM(key, nonce, aad, data)` is AES-256-GCM with a 12-byte nonce and a 16-byte tag appended to the ciphertext.
- `ChunkSize` = 65536 (64 KiB).

## 3. Key hierarchy

| Name | Derivation | Length |
|---|---|---|
| files DEK | 32 random bytes per version, in the tenant's keyring (purpose `files`), wrapped under the KEK; the active version encrypts new files | 32 |
| master key | `HKDF(filesDEK, salt=nil, info="sendora share file encryption v1", L=32)` | 32 |
| file key | `HKDF(master, salt=file salt, info="sendora share file key", L=32)` | 32 |

Since Sendora 0.3 the master key comes from the tenant's `files` DEK, not from the database key. Files written by 0.2 used `HKDF(root, ...)` for the master (root = the database key, or the tenant's platform-derived root): that key is the **legacy key**, and such files are refused until converted (section 8). `info` strings are the ASCII bytes shown, without terminator. The string "v1" in the master-key `info` is a domain label and is **not** the file format version; it stays unchanged in format v2. The file salt is 32 random bytes per file, so every file has its own key. A salt MUST NOT be reused for two files under the same files DEK. Writers MUST draw the salt and the file id from a cryptographically secure random generator and MUST NOT accept them from a caller (other than test code that needs reproducible vectors).

## 4. File layout

### 4.1 Format version 2 (written by 0.1.5 and later)

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | magic | `53 4E 44 46` ("SNDF") |
| 4 | 1 | version | `02` |
| 5 | 32 | salt | random |
| 37 | 16 | fileID | random, also stored in the database row |
| 53 | ... | chunks | see 4.3 |

Header length: 53 bytes.

### 4.2 Format version 1 (legacy, read only)

Written by 0.1.2 to 0.1.4. Layout: magic, version `01`, salt (32), then the chunks. Header length 37 bytes. There is no fileID, and the chunk AAD contains only the last-chunk flag (5.2). Writers MUST NOT produce version 1.

### 4.3 Chunks

The plaintext is split into chunks of `ChunkSize` bytes; only the last chunk may be shorter. Each chunk is stored as `ciphertext || tag`, i.e. plaintext length + 16 bytes. Chunks are stored back to back, without framing.

- Chunk count: `max(1, ceil(plain / ChunkSize))`.
- An **empty file** is exactly one chunk that holds zero plaintext bytes (its 16-byte tag only). This chunk is the last chunk and MUST be authenticated like any other.
- A file whose length is an exact multiple of `ChunkSize` ends with a **full** last chunk. There is no extra empty chunk after it.
- The **last chunk** is the one with index `count - 1`.

### 4.4 Stored size

```
stored = header + plain + 16 * count
header = 53 (v2) or 37 (v1)
count  = max(1, ceil(plain / 65536))
```

Examples (v2): 0 bytes -> 69; 1 -> 70; 65536 -> 65605; 65537 -> 65622 (two chunks). The database row stores `size` (plaintext) and a reader MUST compare the on-disk length with this formula before reading (a mismatch is corruption).

## 5. Nonce and additional data

For chunk index `i` (0-based):

- nonce = `00 00 00 00 || u64be(i)` (12 bytes).
- AAD (v2) = `flag || fileID` (17 bytes), where `flag` is one byte: `01` for the last chunk, `00` otherwise.
- AAD (v1) = `flag` (1 byte).

Because the key is per file, a (key, nonce) pair is used once. The index in the nonce makes chunks position dependent; the flag makes truncation at a chunk boundary and appending detectable; the fileID binds every chunk to the database row (6.3).

## 6. Writer and reader requirements

### 6.1 Writer

1. Generate salt (32) and fileID (16) randomly; derive the file key.
2. Write the 53-byte header, then the chunks in order, computing the plaintext SHA-256 in the same pass.
3. Store the lowercase hex of the fileID (32 characters), a dot and the decimal version of the files DEK in `files.enc_id` (for example `0123...ef.2`), set `files.enc = 1`, and the plaintext SHA-256 in `files.sha256` and the plaintext length in `files.size`.
4. If anything fails, remove the partially written file. A store that is encrypted MUST NOT fall back to writing plaintext when the file key is missing.

### 6.2 Reader

A reader receives the row values `size` and `enc_id`, splits `enc_id` at the last dot into the file id and the DEK version, takes the master key of that version (a version without a dot, or an empty `enc_id`, is the legacy key: the application refuses it; a retired version is refused too), and MUST:

1. Read the first 5 bytes. Magic MUST equal "SNDF"; version MUST be 1 or 2, otherwise refuse (bad header).
2. Accept version 1 **only if** `enc_id` is empty, and version 2 **only if** `enc_id` is non-empty. Any other combination is refused (bad header).
3. Check the stored length against 4.4 for that version (size mismatch).
4. For version 2, compare the header fileID with `enc_id` (id mismatch). The comparison SHOULD be constant time.
5. Derive the file key and authenticate each chunk with the AAD of section 5 before releasing any of its plaintext. For an empty file, authenticate its only chunk when opening.
6. Treat every failure as corruption: no plaintext of a failed chunk is returned, and the error returned to remote clients MUST NOT reveal which check failed, key material or file names.

Random access: because chunks have fixed size and a computable offset, a reader MAY serve a byte range by decrypting only the chunks that overlap it (HTTP Range, media preview). Each decrypted chunk is still fully authenticated.

### 6.3 What the fileID does

In v1, a file copied over another file with the same plaintext size (and the same key) decrypted successfully, because nothing tied the ciphertext to its row. In v2, ciphertext written for row A carries A's fileID in the header and in every chunk's AAD. Copying it over row B's file fails step 4; rewriting just the header id to B's value fails step 5, because the chunk tags were computed with A's id.

## 7. Database encryption (SQLCipher)

The database is SQLCipher 4.20.0 with:

- key: the 32 root-key bytes passed as a raw key (`x'<64 hex digits>'`), not as a passphrase;
- `cipher_page_size` 4096;
- `cipher_hmac_algorithm` HMAC_SHA512 (`cipher_use_hmac` on);
- `cipher_kdf_algorithm` PBKDF2_HMAC_SHA512;
- `cipher_plaintext_header_size` 0: the file has no plaintext header and does not start with "SQLite format 3";
- provider: OpenSSL.

An existing plaintext database is never opened as an encrypted one; it must be migrated offline. These parameters are checked by `internal/store/cipher_params_test.go`.

## 8. Versioning

| Version | Header | Written by | Reader |
|---|---|---|---|
| 1 | 37 bytes, no fileID | 0.1.2 - 0.1.4 | accepted, only with empty `enc_id` |
| 2 | 53 bytes, with fileID | 0.1.5 and later | required for new files |

Version 1 files are not rewritten automatically; they and every file without a key version in `enc_id` are legacy and are converted by the files re-encryption job (`sendora-db files-reencrypt`, or `POST /api/admin/keys/reencrypt-files`), which rewrites them in format v2 under the active files DEK. A future version MUST use a new version byte; readers MUST refuse unknown versions. The `enc_id` column (`TEXT NOT NULL DEFAULT ''`) holds `<fileID hex>.<files DEK version>`; rows with `enc = 0` (plain) and v1 rows keep an empty value, and a bare `<fileID hex>` is a legacy v2 file.

## 9. Auditing

`sendora-db verify-files -source <db> -key-file <key> [-data-dir <dir>] [-json] [-names] [-all] [-progress]` reads every `files` row, verifies header, size, fileID, every chunk tag and the plaintext SHA-256, and lists files on disk without a row (directories inside a share directory are skipped). Status per row: `ok`, `plain-legacy`, `legacy-key` (verifies under the root-derived legacy key; needs conversion), `key-unavailable` (retired or unknown key version), `bad-header`, `size-mismatch`, `id-mismatch`, `tag-fail@chunkN`, `sha-mismatch`, `missing`. Four files are checked in parallel; rows are reported in row id order. By default only rows with a problem and orphans are printed, followed by a summary line; `-all` lists every row. `-json` writes JSON Lines: one object per reported row (`"type":"file"`) and orphan (`"type":"orphan"`), then one `"type":"summary"` object. Progress goes to stderr every 1000 files when stderr is a terminal, or with `-progress`. Output contains a row id and an 8-hex path hash; names are printed only with `-names`; keys, plaintext and raw crypto errors are never printed. The exit status is non-zero if any row fails or any orphan exists.

The startup log line `file encryption active fp=<fingerprint> format=2 sqlcipher=<version>` shows a key fingerprint: the first 8 bytes (hex) of `HMAC-SHA256(root, "sendora key fingerprint v1")`. It identifies a key without revealing it.

## 10. Known limits

- The ciphertext is bound to its row id (fileID) and to nothing else. It is not bound to the share, the file name or the owner. An administrator with database write access and the key can re-point rows.
- A rollback of the **whole** data volume (database and files) to an earlier consistent state is not detected; a restored old backup is valid by construction.
- Files with `enc = 0` (uploaded before 0.1.2) are stored in plaintext. `verify-files` reports them as `plain-legacy` and checks only size and SHA-256.
- The files DEK is wrapped under the KEK. In a platform-managed tenant the operator's key derives that KEK, so the operator can read files; in a tenant-managed tenant only the tenant's own KEK opens it.
- Not encrypted by this format: upload staging parts (`uploads/`), database snapshots made by `snapshot-plaintext`, and branding/background images. These are plain by design or by function.
- File sizes, count, chunk structure and modification times are visible to someone with access to the volume.
- The files key rotates: the next DEK version becomes active, new files use it and the re-encryption job rewrites the others; a version retires once no file uses it. Per-chunk streaming rewrite means a rotation costs one read and one write of every file.
