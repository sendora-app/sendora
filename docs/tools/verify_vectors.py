#!/usr/bin/env python3
"""Independently regenerate internal/filecrypt/testdata/vectors.json (format v2).

Needs the `cryptography` package. Usage: verify_vectors.py [path-to-vectors.json]
Exit status 0 when every vector and every negative vector matches.
"""
import hashlib, json, os, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

CS, TAG, HDR = 65536, 16, 53
hkdf = lambda key, salt, info: HKDF(hashes.SHA256(), 32, salt, info).derive(key)
sha = lambda b: hashlib.sha256(b).hexdigest()
plain_of = lambda n: bytes(i % 251 for i in range(n))

def encrypt(root, salt, fid, plain):
    master = hkdf(root, None, b"sendora share file encryption v1")
    aead = AESGCM(hkdf(master, salt, b"sendora share file key"))
    n = max(1, -(-len(plain) // CS))  # an empty file is one empty chunk
    out = b"SNDF\x02" + salt + fid
    for i in range(n):
        last = i == n - 1
        out += aead.encrypt(b"\0\0\0\0" + i.to_bytes(8, "big"), plain[i * CS:(i + 1) * CS], bytes([last]) + fid)
    return out

def mutate(f, ops):
    f = bytearray(f)
    for o in ops:
        k, off = o["op"], o.get("offset", 0)
        if k == "flip": f[off] ^= 1 << o.get("bit", 0)
        elif k == "set_byte": f[off] = o.get("value", 0)
        elif k == "truncate": del f[off:]
        elif k in ("swap_chunks", "drop_chunk"):
            a = HDR + o.get("a", 0) * (CS + TAG); b = HDR + o.get("b", 0) * (CS + TAG)
            if k == "drop_chunk": del f[a:a + CS + TAG]
            else: f[a:a + CS + TAG], f[b:b + CS + TAG] = f[b:b + CS + TAG], f[a:a + CS + TAG]
    return bytes(f)

def read(f, plain_size, root, row_id):  # reference reader; returns "ok" or the refusal reason
    if len(f) < 5 or f[:4] != b"SNDF" or f[4] != 2 or row_id == "" or len(f) < HDR: return "bad-header"
    n = max(1, -(-plain_size // CS))
    if len(f) != HDR + plain_size + n * TAG: return "size-mismatch"
    if f[37:53].hex() != row_id: return "id-mismatch"
    aead = AESGCM(hkdf(hkdf(root, None, b"sendora share file encryption v1"), f[5:37], b"sendora share file key"))
    for i in range(n):
        raw = f[HDR + i * (CS + TAG):HDR + i * (CS + TAG) + min(CS, plain_size - i * CS) + TAG]
        try: aead.decrypt(b"\0\0\0\0" + i.to_bytes(8, "big"), raw, bytes([i == n - 1]) + f[37:53])
        except InvalidTag: return "chunk:%d" % i
    return "ok"

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../internal/filecrypt/testdata/vectors.json")
    v = json.load(open(path))
    root, salt, fid = bytes(range(32)), bytes(range(0xa0, 0xc0)), bytes(range(0xc0, 0xd0))
    bad = []
    chk = lambda name, got, want: got == want or bad.append("%s: got %s want %s" % (name, got, want))
    chk("root key", v["root_key_hex"], root.hex())
    chk("master key", v["master_key_hex"], hkdf(root, None, b"sendora share file encryption v1").hex())
    chk("file key", v["file_key_hex"], hkdf(bytes.fromhex(v["master_key_hex"]), salt, b"sendora share file key").hex())
    for p in v["vectors"]:
        f = encrypt(root, salt, fid, plain_of(p["plain_size"]))
        chk("size %d" % p["plain_size"], (len(f), sha(f), sha(plain_of(p["plain_size"])), f.hex() if "file_hex" in p else None),
            (p["stored_size"], p["file_sha256"], p["plain_sha256"], p.get("file_hex")))
    base = {}
    for n in v["negative_vectors"]:
        base.setdefault(n["base_plain_size"], encrypt(root, salt, fid, plain_of(n["base_plain_size"])))
        f = mutate(base[n["base_plain_size"]], n["ops"])
        chk(n["name"] + " (hash)", sha(f), n["mutated_file_sha256"])
        chk(n["name"] + " (refused)", read(f, n["row_plain_size"], bytes.fromhex(n["root_key_hex"]), n["row_file_id_hex"]), n["expect"])
    print("\n".join(bad) or "all %d vectors and %d negative vectors match" % (len(v["vectors"]), len(v["negative_vectors"])))
    sys.exit(1 if bad else 0)

main()
