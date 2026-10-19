# Thesis experiment protocol: rigorous reproducible performance and correctness

## 1. Research questions

- RQ1: Apakah evaluasi POLYVAL yang dibagi secara blok dan di-merge dengan pangkat field menghasilkan state/tag/ciphertext yang identik dengan serial dan upstream AES-GCM-SIV?
- RQ2: Bagaimana pengaruh compressed data bytes, ukuran segmen autentikasi, dan thread count terhadap `T_polyval` dan `T_total`?
- RQ3: Kapan overhead Rayon/merge/memory bandwidth menjadikan serial lebih cepat?
- RQ4: Bagaimana perbedaan Zstd single-frame stateful dan independent frames memengaruhi compression ratio, jumlah segmen autentikasi, RSS, disk I/O dan throughput end-to-end?

The algebraic result is a correctness proposition; the empirical speedup is a separate measurable claim.

## 2. Input workloads (document provenance, hashes, security)

- sizes: 256KiB, 1MiB, 4MiB, 16MiB, 64MiB, 256MiB, optionally beyond machine RAM if spool mode.
- entropy classes: highly repetitive, text, structured JSON, mixed/binary, pseudorandom incompressible (seeded).
- prevent any benchmark fixture from containing production PII, key material or real credentials.
- use fixed binary SHA-256 hashes and seed to freeze content.
- `polyval_segment_bytes`: 16KiB, 64KiB, 128KiB, 256KiB, 512KiB, 1MiB (choose based on compressed length; additional 16B/unaligned boundary tests).
- `threads`: 1,2,4,6,8,12 when hardware supports them; also true single-thread serial baseline.
- compression: zstd level and dictionary fixed; single-stateful vs independent-frames explicitly tagged.
- AAD: fixed exact bytes and recorded length; metadata fields must match between comparisons.

## 3. Experimental modes

| Label | Input for timed stage | Primary metric | Correctness prerequisite |
|---|---|---|---|
| `polyval-only` | identical frozen canonical padded POLYVAL blocks | `polyval_ns` + `merge_ns` | same POLYVAL final state |
| `crypto-only` | identical compressed plaintext byte fixture | `encrypt_total_ns` | identical AES-GCM-SIV output |
| `end-to-end` | same raw file + Zstd settings | total upload/download latency, throughput | same compressed output for seq/par arms; decrypt+decompress equal original |
| `independent-frames` | raw file split into Zstd frames | compression ratio and lossless output | do **not** assert equality to single-frame compressed bytes |
| `storage-transport` | encrypted object fixture | PUT/GET, availability, repair time | CRC/hash/Merkle/AEAD verifies; separate from crypto speedup |

`polyval-only` must distinguish field multiplication + reduction from Rayon scheduling + merge; otherwise a good speedup may not carry to end-to-end.

## 4. Experimental procedure

1. Freeze CPU features, Rust version, Cargo.lock hash, git commit, OS/kernel, CPU model, actual physical vs logical cores, memory, turbo/governor and CPU load.
2. Build release via recorded flags and same binary for seq and par. Randomize/alternate execution order across treatments to avoid thermal and cache drift.
3. Verify a fresh correctness trial **before** performance results are accepted; use immutable fixtures shared by seq/par.
4. Warm up; use enough independent trials to estimate spread (suggest >=30 per case when feasible, minimum 10 for exploratory data). Label data under sample threshold as exploratory.
5. Capture both operation timings and full wall clock separately. Do not sum stages and label as e2e if measured at different intervals. Avoid mixing cold I/O with warmed caches.
6. Record throughput using explicit denominator (original MiB or compressed MiB); compression ratios `original_bytes / compressed_bytes`.
7. Compute per-case median, P95 and distribution spread; paired or distributional speedup `median(serial)/median(parallel)` with caveat about skew. Efficiency `speedup / thread_count` for fixed workload, not a CPU utilization metric.
8. Test with `compressed_bytes < segment_bytes` and `compressed_bytes > 2*segment_bytes` explicitly; label `parallel_not_exercised` if <=1 segment.
9. Report meaningful regressions, not only best results. Distinguish crypto microbench from end-to-end improvement and prove practical benefit under realistic compressed-data sizes.
10. Where test metadata incomplete (e.g., tag not captured), correctness status = `NOT VERIFIED`, not PASS.

## 5. Machine-readable JSONL format for scripts/summarize_bench.py

One object per measured trial, example:

```json
{"case_id":"polyval-4m","bench_kind":"polyval-only","implementation":"sequential","trial":1,"original_bytes":4194304,"compressed_bytes":4194304,"polyval_bytes":4194304,"segments":64,"segment_bytes":65536,"threads":1,"total_ns":900000,"tag_hex":"0123456789abcdef0123456789abcdef"}
{"case_id":"polyval-4m","bench_kind":"polyval-only","implementation":"parallel","trial":1,"original_bytes":4194304,"compressed_bytes":4194304,"polyval_bytes":4194304,"segments":64,"segment_bytes":65536,"threads":12,"total_ns":300000,"tag_hex":"0123456789abcdef0123456789abcdef"}
```

Fields required: `case_id`, `bench_kind`, `implementation` (`sequential`/`parallel`), `trial`, `original_bytes`, `compressed_bytes`, `polyval_bytes`, `segments`, `segment_bytes`, `threads`, `total_ns`. Optional: `tag_hex` (32 hex characters), `ciphertext_sha256` (64 hex), `compression_ns`, `polyval_ns`, `merge_ns`, `ctr_ns`, `encrypt_total_ns`, `peak_rss_bytes`, `git_commit`, `dataset_sha256`, `rustc`, `zstd_mode`, `zstd_level`.

Pair by `(case_id, bench_kind, trial)` only if the same content and configuration is used. At minimum the groups must agree on `original_bytes`, `compressed_bytes`, `polyval_bytes`, `segment_bytes`, `bench_kind`. For **whole-message** same key/nonce/AAD, compare tag/ciphertext hash. For `independent-segment-aead`, never do direct tag equivalence comparison.

Python script is a reporting aid, not replacement for Criterion, perf instrumentation, or raw timing evidence. Reports with fewer trials are warnings, not silent academic conclusions.

## 6. User-supplied checkpoint results (historical, unverified here)

Environment: Linux x86_64; 12 CPUs, Rayon 12 threads; `aes`, `pclmulqdq`, `avx2`, `vpclmulqdq`, `vaes`; rustc 1.99.0; release profile.

Quick POLYVAL-only samples:

| Input | Seq us | Parallel us | Speedup | Parallel eff/12 |
|---|---:|---:|---:|---:|
| 256 KiB | 55.5 | 90.3 | 0.61x | 0.05 |
| 1 MiB | 210.4 | 104.5 | 2.01x | 0.17 |
| 4 MiB | 870.6 | 281.1 | 3.10x | 0.26 |
| 16 MiB | 3307.5 | 1453.9 | 2.27x | 0.19 |

Regression at 256 KiB matters. Drop at 16 MiB may have multiple causes; do not assert memory bandwidth bottleneck without profiling. The most favorable 3.10x is **an exploratory observation**, not thesis confidence interval. `polyval-only` throughput may appear higher than end-to-end throughput because it excludes compression, AES-CTR, memory copies, storage and transport.

Pipeline sample: 4 MiB original => 3,936 B across 32 independent Zstd frames vs 496 B in one frame. `POLYVAL segments = 1` with 65,536 B setting, despite the 32 frames. This shows neither large multi-segment execution nor end-to-end improvement from parallel POLYVAL. Original Zstd benchmark must cover realistic incompressible data as well.

## 7. Amdahl sanity check

If compression time is 2666 us and combined encryption time only 19 us in the sample, even infinitely fast encryption saves at most `19/(2666+19) ~= 0.71%` of **compress+encrypt** time for that workload (other stages excluded). This is not a general bound for different workloads. Evaluate with less-compressible inputs before optimizing away a tiny stage.

## 8. Research output checklist

For each figure/table: source dataset SHA256, run command, commit hash, environment, N, P50/P95, speedup + units, error bars if meaningful, counterexamples, correctness oracle result and caveats. Distinguish informal preliminary logs from final thesis measurements. Never cherry-pick one best run.
