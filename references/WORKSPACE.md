# Workspace contract (supplied baseline, not audited source)

## Manifest root (as provided)

```toml
[workspace]
resolver = "3"
members = [".", "crates/crypto", "crates/zstd", "crates/ipfs", "crates/web", "crates/rest"]

[workspace.dependencies]
polyval = { version = "0.7.3", features = ["hazmat"] }
aes-gcm-siv = "0.12.1"
universal-hash = "0.6.1"
cipher = "0.5.2"
aes = "0.9.3"
ctr = "0.10.1"
rayon = "1.12.0"
zstd = "0.14.2"
tokio = { version = "1.53.2", features = ["rt-multi-thread", "macros", "fs", "io-util", "net", "sync"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
hex-literal = "1.1.0"
criterion = "0.8.2"
bytemuck = "1.25.2"
memmap2 = "0.9.11"
todo-crypto = { path = "crates/crypto" }
todo-zstd = { path = "crates/zstd" }
todo-ipfs = { path = "crates/ipfs" }
todo-web = { path = "crates/web" }
todo-rest = { path = "crates/rest" }

[package]
name = "parallel_aes_gcm_siv"
version = "0.1.0"
edition = "2024"
default-run = "parallel_aes_gcm_siv"

[dependencies]
todo-crypto = { workspace = true }
todo-zstd = { workspace = true }
todo-ipfs = { workspace = true }
todo-web = { workspace = true }
todo-rest = { workspace = true }
rayon = { workspace = true }
tokio = { workspace = true }
polyval = { workspace = true }
aes-gcm-siv = { workspace = true }
zstd = { workspace = true }
serde_json = { workspace = true }

[dev-dependencies]
criterion = { workspace = true }
hex-literal = { workspace = true }

[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
```

Do not overwrite actual Cargo.toml with this reference. Keep the authoritative Cargo.lock, and `cargo metadata --format-version 1 --no-deps` to resolve local dependency graph.

## Proposed responsibilities (verify actual crate modules first)

- **`todo-crypto`**: `PolyvalBackend::{Sequential,Parallel}`, `PolyvalParams{segment_bytes,threads}`, stable `encrypt/decrypt` adapter, public verification. `KeyMaterial` MUST be protected; API and trait names are examples, not existing symbols.
- **`todo-zstd`**: `CompressionMode::{SingleFrameStateful,IndependentFrames}`, stateful encoder and bounded producer, decoder limits and metadata.
- **`todo-ipfs`**: adapters for in-memory mock vs real IPFS, CID parser, encrypted object blobs, manifests, verification + recovery logic.
- **`todo-rest`**: request input validators, object/experiment API handlers, error schema. No key schedule or cipher directly.
- **`todo-web`**: scorecards, experiment plots, object health, attack/repair events, exact export statuses; no secret material to client.
- **root**: cross-crate orchestration, `src/main.rs` thin, `benches/` experiments, `tests/` integration only if actually present.

## Engineering rules

1. Use immutable immutable input slices and small typed structs where possible. Avoid `Arc<Mutex<Vec<u8>>>` for huge buffers.
2. `rayon` handles CPU bound parallel transformations; `tokio` for I/O scheduling. Prefer bounded channels/backpressure.
3. Avoid whole-file `Vec<u8>` if file size unbounded. For single-tag AES-GCM-SIV, use secure rewindable compressed spool; impose disk and RAM limits.
4. Handle cancellation, partial writes, fsync/publish semantics and cross-filesystem rename safely. Do not silently drop corrupt objects.
5. Prefer compatibility with x86_64 acceleration but include generic portable path; choose ISA using capabilities detected at runtime, not assumption based on test host.
6. Never print secret keys/expanded schedules or actual customer content in logs. Use sample data with deterministic seed for benches, cryptographic randomness for key/nonce.
7. A security-sensitive benchmark implementation must be instrumented separately from production functions; avoid changing correctness for performance knobs.
8. Avoid gratuitous new dependencies; check API compatibility of `polyval`, `universal-hash`, `aes-gcm-siv`, `cipher` and `aes` versions.

## Git discipline

- Inspect `git status --short`; do not destroy uncommitted work.
- Make minimal deltas and preserve API tests.
- If multiple crate manifests need changes, list each and explain the dependency edge.
- Always show actual paths and `cargo` commands run or why not run. Never claim tested when only a reference manifest exists.
