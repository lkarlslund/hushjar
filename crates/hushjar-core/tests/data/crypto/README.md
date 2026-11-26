# Cryptographic compatibility vectors

`pbkdf2.json` contains the pinned SDK's 10,000-iteration vector and independent
Python `hashlib.pbkdf2_hmac` outputs at 5,000, 600,000 and 2,000,000 iterations.
The manifest identifies exact sources and reproduction steps. These synthetic
values are never real account credentials. Do not regenerate expected results
with VaultGoblin's implementation.

The implementation uses Go's standard `crypto/pbkdf2` with SHA-256, normalized
legacy email as salt, and a 32-byte output. Its explicit local iteration ceiling
matches the pinned legacy client's settings maximum. The upstream prelogin
validator itself only checks the minimum; larger accounts are currently refused,
not silently downgraded. Parameter pinning and work admission are separate work.

Clearing the temporary password byte slice is best effort: Go strings, compiler
copies and the standard primitive prevent a claim of complete memory erasure.
Key stretching and authorization-hash vectors are now covered; there is no server round-trip proof yet.

`argon2id.json` retains the pinned SDK vector and adds independent libargon2
outputs for minimum/default costs and non-divisible memory/lane geometry.
`generate-argon2id.py` records the reproducible synthetic oracle. Validation
checks 16–1024 MiB, 2–10 iterations and 1–16 lanes before conversion; no
1 GiB allocation is needed to test parameter validation. The upper limits are
explicit local support limits matching upstream settings, not universal
prelogin limits. KDF concurrency admission and downgrade protection are pending.

Dependency scan on 2026-09-14 found no affected imported packages. Its module
report includes GO-2026-5932 for `golang.org/x/crypto/openpgp`; this package is
not imported or vendored by VaultGoblin. The client uses `argon2` and its
`blake2b` dependency from pinned `golang.org/x/crypto v0.57.0`.

`stretch.json` contains the pinned SDK HKDF-Expand enc/mac vector.
`auth-hash.json` contains the SDK server-authorization result and an independent
Python-derived local-authorization result, with exact provenance/reproduction
metadata. Tests also exercise full PBKDF2 and Argon2id to server-authorization
chains against SDK expectations. Unknown purposes and invalid master-key lengths
are rejected. Authorization hashes remain sensitive credentials.

`type2.json` uses an independent OpenSSL 3.6.4 AES-CBC / Python HMAC oracle.
`generate-type2.py` recreates its original synthetic inputs and outputs, including
authenticated invalid padding. Decryption tests mutate every IV/ciphertext/MAC
byte and MAC-key byte. The encryption-key half is not independently bound by the
legacy MAC; this format assumes a coherent trusted encryption/MAC key pair.

Encryption tests compare output byte-for-byte with the valid `type2.json`
envelopes using their deterministic IV through a private test seam. The public
encryption entry point uses crypto/rand, accepts no entropy argument, and is
tested separately for fresh-IV readback and input bounds.
