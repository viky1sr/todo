# Academic guardrails for S2 thesis

## Locked framing

**Judul:** *Komposisi Paralel POLYVAL pada Segmen Zstandard untuk AES-GCM-SIV*.

The user-provided abstract argues that parallel POLYVAL on segmented Zstd-compressed data can improve authentication bottlenecks while preserving mathematical equivalence and cryptographic properties. Treat this as **research hypothesis**, not established empirical result. A fixed segment size or optimal thread count must be derived experimentally.

## Contributions and limitations

- **Mathematical:** prove a parallel ordered composition for contiguous canonical POLYVAL blocks, with correct GF(2^128) `dot` semantics and strict AAD/payload padding/length block treatment. State all assumptions.
- **Engineering:** implement concurrent local hashing and ordered merge with correct single-message AES-GCM-SIV tag, portable fallback and bounded memory.
- **Empirical:** contrast throughput/latency serial vs parallel, by compressed output size, segment count, Rayon threads, workload entropy, and Zstd frame strategy; publish negative results too.
- **Not automatically novel:** polynomial hashing parallelism, AES-GCM-SIV, Zstd, IPFS, Merkle trees and distributed storage. Review literature before claiming first-of-kind.

## Bibliographic evidence policy

Use at least **30 verifiable peer-reviewed publications** for the thesis corpus if academically required by the user; record publisher venue, year, DOI, exact scope, what result supports/does not support hypothesis. Accept major peer-reviewed venues from ACM, IEEE, Springer, Elsevier and comparable journal/conference publishers.

- RFC 8452 and RFC 8878, NIST publications are **technical references**, not peer-reviewed demonstration of the thesis gap.
- arXiv/ePrint can provide background/preprint versions, **not the primary basis** for gap claims; seek the published peer-reviewed version.
- PhD dissertations can support related background/method but do not substitute a peer-reviewed article when bibliography criteria require one.
- Never fabricate bibliographic entries, DOIs, benchmark results, or paper quotes. Do not claim 30 references have been verified when that work has not been done.

## Literature matrix

For each verified reference, capture:

`citation, DOI/URL, venue, peer-reviewed? (evidence), year, problem, primitive, parallelism, dataset/hardware, metrics, method, limitation, relationship to thesis, overlap/gap, quality concerns`.

Search terms: `POLYVAL parallel reduction`, `GCM-SIV performance`, `nonce misuse-resistant AEAD implementation`, `field multiplication vectorization`, `compression encryption pipelines`, `Zstandard streaming performance`, `authentication on compressed data`, `AEAD hardware acceleration`.

## Logical reporting structure

1. Motivation and exact focus; why Zstd+AES-GCM-SIV+POLYVAL combined system needs evaluation.
2. Precise problem statement/hypotheses: mathematical equality, impact of segment size, overhead and crossover point.
3. Literature comparison, identify prior art and limitations; question novelty upfront.
4. Formal representation in GF(2^128), lemma, proof for ordered segments and padding assumptions.
5. Architecture and implementation Rust, correctness oracle, threat assumptions.
6. Experimental methodology with reproducible hardware/software/workload matrix.
7. Results: all distributions, equal tags/ciphertext, throughput vs compressed data/threads, end-to-end tradeoffs and statistical limitations.
8. Validity threats, side-channel issues, deployment/production caveats, future research.

Claims must be scoped: serial=parallel for tested inputs is empirical evidence; algebraic identity is proof under assumptions; cryptographic security relies on standard construction and implementation; practical speedup must exceed measurement noise and orchestration overhead.
