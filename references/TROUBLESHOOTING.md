# Rust root troubleshooting and environment checks

## `No such file or directory`

1. Inspect `pwd`, `ls -la`, `find . -maxdepth 2 -name Cargo.toml`, output path, source file existence and symlink chains.
2. Run helper from **repo root** or pass `--root /path/to/repo`: `bash scripts/check_workspace.sh --root . --mode preflight`.
3. Create parents before writing with `mkdir -p` **only when the intended output path is verified**; never hide missing input file by making a fake placeholder.
4. For temp encrypted spool, create path using safe temp dir and atomic commit into existing storage namespace; verify permission/ownership and available disk.
5. Keep root-relative path calculations derived from script location, not user's shell current directory.

## Dependency and compiler mismatches

- Record `rustc --version`, `cargo --version`, root `Cargo.toml` and committed `Cargo.lock` checksum; **edition 2024 requires compatible toolchain**.
- `cargo metadata --no-deps --format-version 1` reveals actual members; do not assume package names equal crate directories.
- `cargo tree -d` exposes duplicate major versions, but duplicates alone are not automatically bugs.
- For `polyval`, `universal-hash`, `cipher`, `aes` and `ctr`, check actual trait APIs and crate feature flags before casting or importing; investigate conflicting library versions carefully.
- Log full `cargo check --workspace --all-targets` errors before modifying dependencies; do not blindly upgrade pinned versions.

## Rayon throughput anomalies

- Case 256KiB showed parallel slower than sequential in user-supplied quick run; this is a valid overhead observation.
- Compare thread counts and CPU topology; logical 12 CPUs are not necessarily 12 physical cores.
- Check compression output length vs segment bytes; if one segment, Rayon cannot distribute local POLYVAL hash work across multiple chunks.
- Separate `local_polynomial_work_ns`, `rayon_schedule_ns`, `merge_ns`, `aes_ctr_ns`, `compression_ns` and end-to-end; median across repeated, alternated trials.
- Evaluate memory bandwidth/cache hypotheses with profiling (e.g. Linux perf if permitted); do not assert them without profiling evidence.
- `RUSTFLAGS="-C target-cpu=native"` may optimize locally but breaks binary portability; record build flags exactly and keep a portable comparison.

## Bad CID despite mock roundtrip

Historical mocked ID `bafybeigf7b969b0912a860600000073` contains characters outside lowercase Base32 for CIDv1; use `python3 scripts/check_cid.py <cid>` to detect format problems. Passing structural CID validation still does **not** verify actual stored object content or backend availability.

## Claims and provenance

Do not confuse historical logs with tests run in the current checkout. If only user-provided manifests/logs are available: say `source code not supplied`, `build NOT RUN`, `bench NOT RUN`, but provide accurate recipes and skill files.
