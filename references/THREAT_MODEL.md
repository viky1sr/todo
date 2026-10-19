# Threat model and protective testing

## Assets and adversaries

Protect plaintext source data, derived compressed plaintext, AEAD key and nonce context, immutable ciphertext/tag, authenticated metadata, manifest, canonical root, replica placement and repair authority. Consider external client, malicious storage node, corrupted disk, insider with partial access, compromised datacenter and passive size/timing observer. Distinguish adversary with read-only object access from adversary who can modify authoritative manifest/root or steal keys.

## Mandatory assumptions

- AES-GCM-SIV is as specified in RFC 8452 and implemented correctly using trusted primitives; side-channel behavior of custom POLYVAL field code is independently assessed.
- TLS for network, strong server-side key management, per-object nonce policy and authenticated AAD schema.
- Compress-then-encrypt does not hide ciphertext length or timing. Compression may reveal information in attacker-controlled-input scenarios; do not claim segmenting POLYVAL is a compression-side-channel mitigation.
- Deduplication, content addressing and compression of shared secrets can cause additional leakage; separate tenant security contexts and analyze whether attacker can influence compressed plaintext.
- Nonce reuse tolerance is bounded, not equivalent to safe unlimited reuse.

## Security review gates

1. **Tags:** one 16-byte tag per message; independently segmented AEAD has different nonce/tag semantics; reject tampered ciphertext, AAD, nonce and tag.
2. **Authentication-before-release:** never expose plaintext/decompressed output or partial client-visible chunks until authentication succeeds. Enforce decompressed output quotas before writing or sending.
3. **Key hygiene:** never hardcode real keys, prevent keys appearing in logs, error bodies and browser state; rotate and revoke when compromised.
4. **Memory safety:** bound queues, allocations, mmap offsets, file sizes, frame count and maximum authenticated/decompressed bytes; use checked arithmetic.
5. **Filesystem:** use safe temp paths, no traversal/symlink races, securely scoped storage, atomic commits, recovery from power failure.
6. **Integrity:** verify CID structural validity and (where required) actual content digest; verify Merkle leaves against trusted root; do not accept proof to client-provided unsigned root.
7. **Replication:** authorize node identity, enforce failure-domain diversity, quarantine suspicious replicas, audit repair with canonical evidence.
8. **Denial-of-service:** bounds on concurrency, HTTP request/response bodies, job lifetime, decompression ratio, benchmark job CPU and disk quotas.
9. **Cross-platform:** runtime CPU feature detection and portable fallback; record hw dispatch path used by benchmark; do not assume acceleration equals constant-time by default.
10. **Disclosure:** tests use synthetic data and controlled fault injection. Do not write tools to attack third-party systems.

## Fault injection matrix

| Inject | Expected defensive behavior |
|---|---|
| corrupt one ciphertext byte | AEAD verify FAIL, no plaintext release |
| flip tag/AAD byte | verify FAIL and cleanup |
| malformed Zstd stream | fail decoding after successful AEAD verification if encrypted blob is well-authenticated but invalid compressed syntax |
| valid but huge decompression | bounded output / budget reject |
| erase replica | DEGRADED, verified recovery if valid source exists |
| rewrite untrusted manifest | signature/root mismatch -> reject |
| stale object generation | reject rollback, no silent overwrite |
| untrusted fake node | unauthorized ACK/repair rejected |
| crash after write before commit | temp cleanup or resumable transaction, object not visible |
| unavailable all replicas | UNRECOVERABLE or PENDING, never fabricate recovery success |
