# Parallel POLYVAL thesis code update

Target thesis path:

`Zstandard single compressed stream -> logical POLYVAL segments -> ordered parallel tree composition -> one AES-GCM-SIV tag`

## Files changed

- `crates/crypto/src/gf128.rs`
- `crates/crypto/src/polyval_seq.rs`
- `crates/crypto/src/polyval_par.rs`
- `crates/crypto/src/aes_gcm_siv_par.rs`
- `crates/crypto/src/adaptive.rs`
- `crates/crypto/src/lib.rs`
- `crates/crypto/src/tag_equivalence.rs`
- `crates/crypto/benches/polyval_benchmark.rs`
- `crates/crypto/tests/equivalence_proof.rs`
- `crates/crypto/tests/rfc8452_vectors.rs`

No Cargo dependency change is required for the workspace versions supplied with the project.

## Important behavior changes

1. `PolyvalPart` is now a self-contained composition state `(P, n, H^n)`.
2. `polyval_parallel()` now uses an ordered Rayon tree reduction for composition.
3. `polyval_parallel_linear_reduce()` preserves the previous parallel-local + sequential-fold shape as a benchmark baseline.
4. AES-GCM-SIV execution is separated into:
   - `SS`: sequential POLYVAL + sequential CTR.
   - `PS`: parallel POLYVAL + sequential CTR. **Primary thesis method.**
   - `SP`: sequential POLYVAL + parallel CTR. Control experiment.
   - `PP`: parallel POLYVAL + parallel CTR. End-to-end optimized experiment.
5. `aes_gcm_siv_encrypt_planned()` / `decrypt_planned()` now use **PS**, so adaptive Zstandard pipeline measurements isolate the POLYVAL contribution.
6. AAD remains sequential in the PS/PP POLYVAL path. Only message bytes (the compressed Zstandard stream in the pipeline) are segmented.
7. The old `aes_gcm_siv_encrypt_parallel()` and `decrypt_parallel()` names remain available and mean PP for backwards compatibility.

## Zstandard thesis mode

For the thesis experiment use the existing single-frame constructor, not the default independent-frame baseline:

```rust
let pipeline = StreamCryptoPipeline::single_frame(3);
```

This keeps Zstandard as one logical compressed stream. POLYVAL segmentation happens after compression and does not create independent Zstd frames.

## Selectable `crypto_mode`

The compressed stream can be encrypted with one of six modes (default `aes-gcm-siv`):

| `crypto_mode` | Primitive | Tag | Notes |
|---|---|---|---|
| `aes-gcm-siv` | AES-GCM-SIV (RFC 8452) | 16 B | primary thesis mode, segment-parallel POLYVAL, wire format v1 unchanged |
| `xchacha20` | XChaCha20 | none | **unauthenticated** baseline (cost of authentication); must be named explicitly to decrypt |
| `xchacha20-poly1305` | XChaCha20-Poly1305 | 16 B | |
| `ascon-aead128` | Ascon-AEAD128 (NIST SP 800-232) | 16 B | |
| `aegis-256` | AEGIS-256 | 32 B | |
| `cascade-xchacha20poly1305-aegis256` | XChaCha20-Poly1305 inside AEGIS-256 | 16 B inner + 32 B outer | independent HKDF subkeys |

```rust
use todo_zstd::{CryptoMode, StreamCryptoPipeline};
let pipeline = StreamCryptoPipeline::single_frame(3).with_crypto_mode(CryptoMode::Aegis256);
```

```bash
cargo run --release -- --list-crypto-modes
cargo run --release -- --crypto-mode xchacha20-poly1305   # or CRYPTO_MODE=... / --mode-crypto
cargo test -p todo-crypto --test crypto_mode_vectors       # published KATs + tamper tests
cargo test -p todo-zstd --test crypto_modes_pipeline
cargo bench -p todo-crypto --bench crypto_modes_benchmark  # crypto-only, per mode
```

### Parallel STREAM chunking for non-AES modes

`--stream-chunk-size <bytes>` (env `STREAM_CHUNK_SIZE`, REST `stream_chunk_size`, web "Chunk STREAM paralel"; 1 KiB..1 GiB, non-AES only) seals the compressed stream as independent AEAD chunks on the Rayon pool (STREAM, Hoang–Reyhanitabar–Rogaway–Vizár, CRYPTO 2015; format version 3). Chunk `i` uses nonce `base[..len-5] || u32 BE i || is_last` and AAD `header || crypto_mode_id || i u64 LE || is_last`, so swapped, duplicated, dropped, appended or spliced chunks fail authentication. All chunks are verified before any byte is decompressed. Each chunk costs one extra tag (16/32/48 B).

```rust
let pipeline = StreamCryptoPipeline::single_frame(3)
    .with_crypto_mode(CryptoMode::Aegis256)
    .with_stream_chunking(Some(64 * 1024))?;
```

```bash
cargo run --release -- --crypto-mode aegis-256 --stream-chunk-size 65536
cargo test -p todo-crypto --test stream_chunking
cargo test -p todo-zstd --test stream_chunking_pipeline
```

REST/web: optional `"crypto_mode"` field on `pipeline/process`, `pipeline/recover`, `pipeline/verify`, `ipfs/publish`, `ipfs/fetch`; `GET /api/v1/crypto-modes` lists the modes. Non-AES modes are different formats (sealed stream version 2, mode id in the AAD): compare throughput, never tags, with AES-GCM-SIV. Details: `references/CRYPTO_CORRECTNESS.md`.

## Manual validation commands

Run from the workspace root:

```bash
cargo fmt --all -- --check
cargo test -p todo-crypto
cargo test -p todo-zstd
cargo test --workspace
```

Then run the research benchmarks in release mode:

```bash
cargo bench -p todo-crypto --bench polyval_benchmark
```

To compare worker counts explicitly:

```bash
RAYON_NUM_THREADS=1 cargo bench -p todo-crypto --bench polyval_benchmark
RAYON_NUM_THREADS=2 cargo bench -p todo-crypto --bench polyval_benchmark
RAYON_NUM_THREADS=4 cargo bench -p todo-crypto --bench polyval_benchmark
RAYON_NUM_THREADS=8 cargo bench -p todo-crypto --bench polyval_benchmark
```

## What must pass before benchmark results are used in the thesis

- RFC 8452 vectors pass.
- `SS == PS == SP == PP == upstream` for ciphertext and tag.
- Tree POLYVAL == linear-reduce POLYVAL == sequential POLYVAL.
- Odd/even segment counts and final partial blocks pass.
- Zstandard single-frame round trip passes.

## Validation note for this ZIP

The files were statically inspected and delimiter-balanced in the generation environment. That environment did **not** contain `cargo`, `rustc`, or `rustfmt`, so compilation/tests could not be executed here. Run the commands above in your Rust workspace before accepting benchmark results.

`CHANGES.patch` is included for manual review against the uploaded source.
