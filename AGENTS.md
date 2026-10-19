# Agent instructions — parallel_aes_gcm_siv root repository

Read [SKILL.md](SKILL.md) **before** changing this Rust workspace; it is the authoritative project Skill. Consult only the relevant `references/*.md` for the affected crate or research task.

## Repository contract

Workspace: Rust 2024, resolver 3, root binary `parallel_aes_gcm_siv`; members `crates/crypto`, `crates/zstd`, `crates/ipfs`, `crates/web`, `crates/rest`. Treat current `Cargo.toml` and `Cargo.lock` as authoritative. Named crate packages from baseline are `todo-crypto`, `todo-zstd`, `todo-ipfs`, `todo-web`, `todo-rest`.

## Priorities

1. Preserve byte-identical AES-GCM-SIV output (single compressed plaintext message, one tag) when moving from serial to parallel POLYVAL; verify against RFC 8452 and upstream `aes-gcm-siv`.
2. Do not treat Zstd frames, POLYVAL chunks and AEAD messages as equivalent boundaries. Exactly one AAD pad, compressed plaintext pad and terminal length block in whole-message mode.
3. No plaintext release before AEAD tag verification. Protect keys, authenticated metadata, sizes and temporary files; budget memory/disk and decompression output.
4. Parallel speedup must be measured and cannot be claimed when compressed output yields one segment. Keep crypto-only measurements separate from end-to-end throughput.
5. Keep IPFS mock and live IPFS distinct, validate CID structure, and only repair replicas using verified canonical ciphertext.
6. Do not invent repository files, API names, passes, academic references or benchmark results.

## Working agreement

- Inspect paths, Git status and existing code. Make minimal diff. Define affected security and research invariants.
- Run `bash scripts/check_workspace.sh --root . --mode preflight`, then `--mode check` and release tests only when appropriate; record PASS/FAIL/NOT RUN accurately.
- Report touched file paths, exact commands, correctness oracle, benchmark configuration, failures and honest limitation.
- Preserve thesis scope and academic requirements: mathematical identity plus empirical Rust benchmark; at least 30 peer-reviewed verified publications when composing literature, no fabricated DOI, RFC/NIST as specifications only.

Read [references/WORKSPACE.md](references/WORKSPACE.md), [references/CRYPTO_CORRECTNESS.md](references/CRYPTO_CORRECTNESS.md), [references/EXPERIMENT_PROTOCOL.md](references/EXPERIMENT_PROTOCOL.md) and the rest only as needed.
