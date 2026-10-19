# Crypto correctness: RFC 8452, POLYVAL and parallel combination

## Scope

AES-GCM-SIV authenticates `AAD || pad_16 || P || pad_16 || length_block`, where **P is compressed plaintext** in this project. Ciphertext is obtained only after computing the synthetic tag. The fact that compressed bytes are divided into CPU work segments does not create multiple AEAD messages.

Official implementation specification: https://www.rfc-editor.org/rfc/rfc8452.html (Sections 3–5, Appendix C). Treat this as a technical specification rather than a peer-reviewed novelty claim.

## RFC invariants

- AES-GCM-SIV uses a 12-byte nonce, a 16-byte (AES-128) or 32-byte (AES-256) key, with **per-nonce** authentication/encryption subkeys derived as specified in Section 4.
- POLYVAL field: GF(2^128), reduction polynomial `x^128 + x^127 + x^126 + x^121 + 1`, little-endian bit mapping of field elements, and `dot(a,b)=a*b*x^(-128)` where `*` is standard field multiplication.
- For input blocks X_1 ... X_N in RFC order: `S_0=0`, `S_i=dot(S_(i-1) XOR X_i,H)`.
- AAD is zero-padded **as one stream** to 16B; compressed plaintext is independently zero-padded **as one stream** to 16B. Append exactly one 16B little-endian length block containing **bit lengths** of AAD and plaintext (64 bits each).
- XOR nonce into the low 12 bytes of state, clear high bit of last byte, encrypt with derived message-encryption key to obtain 16-byte tag.
- CTR initial block is derived from tag (high bit of last byte set); CTR increments low first 32 bits in little-endian; encrypt **unpadded P**. Output ciphertext||tag (16 bytes overhead for one message).
- Enforce RFC-defined message limits (Section 4). Decrypt may stage unauthenticated P internally but **must not release it** until constant-time tag verification succeeds.

## Derivation for parallel POLYVAL (one AEAD message)

Define `B = H * x^(-128)` in the field and `T_H(s)=s*B`. Thus `S_i=T_H(S_(i-1) XOR X_i)=T_H(S_(i-1)) XOR T_H(X_i)` by linearity.

For a contiguous list of n canonical POLYVAL blocks `U`, let `P_U` be its hash from zero state. For adjacent lists `U` length n and `V` length m with zero-state local hash `P_V`, linear recurrence yields:

`POLYVAL(U || V) = T_H^m(P_U) XOR P_V`.

Therefore associate each consecutive segment with `(local_hash, count_of_16B_blocks)` and combine in left-to-right order:

`combine((P,n),(Q,m)) = (T_H^m(P) XOR Q, n+m)`.

For segments 1..k:

`S = XOR_j T_H^(sum_{l>j} n_l)(P_j)`.

The ordered operator is associative under **consecutive input ranges**. Local hashes can be computed concurrently; final reduction must preserve each segment's original position/length. Correct field exponentiation can use exponentiation by squaring; test independent algebra implementation against serial reference. Do not accidentally use `dot` powers as normal field powers.

### Block segmentation rule

Split the **canonical block sequence** after AAD padding and P padding are applied at their real boundaries. Neither independent Zstd-frame boundaries nor arbitrary byte offsets are inherently POLYVAL block-aligned. If using a compressed-byte streaming producer, maintain a carry buffer for 0–15 tail bytes; do not pad each chunk. Ensure AAD and length block are processed once. These details are part of the proof assumptions.

## What the proof does NOT establish

- It does not prove the security of a novel AEAD construction (none is proposed).
- It does not show speedup or energy improvement; that requires measurements.
- It does not make independent per-segment AEAD tags equal the one-tag mode.
- It does not establish that key/nonce reuse is harmless; follow RFC Section 9.
- It does not mean `encrypt()` can emit early final ciphertext before the single tag is ready.

## Required testing matrix

1. RFC 8452 Appendix C vectors for both key lengths and counter-wrap tests where applicable.
2. `aes-gcm-siv` upstream oracle, same key/nonce/AAD/P, compare tag **and ciphertext** bit-for-bit.
3. Input lengths: 0, 1, 15, 16, 17, 31, 32, 33, 65535, 65536, 65537 bytes; AAD: 0,1,15,16,17, long.
4. Segment counts: 1,2,3,4, odd, non-power-of-two, >physical threads; segment sizes causing 16-byte boundaries and carry cases.
5. Distinct keys, nonces, deterministic pseudorandom input, repetitive and incompressible payloads.
6. Tamper AAD, ciphertext, tag, nonce, compressed header and length metadata; verify reject before plaintext/decompression exposure.
7. Test 128-bit field operations independently: identity, distributivity, known RFC field-operation examples, combinator associativity, and block-count powers.
8. Negative boundary cases: too large payload/AAD, invalid key size, truncated tag, truncated compressed stream, input decoding errors.
9. Verify lossless `(original -> compress -> AEAD encrypt -> verify/decrypt -> decompress) == original`.
10. Cross-check memory safety and architecture-specific accelerated vs portable paths; CPU feature detection cannot be treated as security validation.

## Acceptance gate

`PASS` means RFC vectors, serial=parallel and upstream byte-for-byte equality, negative tamper tests, and roundtrip for multi-segment cases. Store exact test command, git commit, rustc version, seed, and error output if failing. `NOT RUN` when repo sources/CPU are not accessible.
