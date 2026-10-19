# REST/Web integration contract (proposals, inspect actual routes first)

## Layers

`REST controller -> application service -> todo-zstd + todo-crypto -> todo-ipfs adapter -> persistence`, while UI consumes only validated REST models and public status. This is a **proposed** decomposition, not a claim existing Rust code uses these handlers.

Suggested versioned endpoints (adapt to actual routes):

| HTTP | Path | Result |
|---|---|---|
| POST | `/api/v1/experiments` | enqueue validated benchmark job; no arbitrary server-side commands |
| GET | `/api/v1/experiments/{id}` | environment, params, correctness, distributions, warnings |
| POST | `/api/v1/objects` | upload with bounded streaming, responds after durable authenticated commit |
| GET | `/api/v1/objects/{id}` | metadata, generation, encryption algorithm, replica states |
| GET | `/api/v1/objects/{id}/content` | stream **after AEAD verify**, with output size policy |
| GET | `/api/v1/objects/{id}/integrity` | trusted canonical root, status, proof summary |
| POST | `/api/v1/objects/{id}/verify` | authenticated request, rate-limited verification job |
| POST | `/api/v1/objects/{id}/repair` | authorized maintenance job (no direct trust in client proof) |
| GET | `/api/v1/health` | readiness without secret data |

## API safety

- Reject path traversal, arbitrary filesystem paths, oversized data, unexpectedly large decompression, invalid MIME/type claims, untrusted client-supplied shell commands and unreasonable benchmark thread counts.
- Use clear machine-readable errors (400 invalid request, 401/403 unauthorized, 404 missing, 409 generation conflict, 413 too large, 422 cryptographic/format invalid, 429 throttled, 503 backend unavailable).
- Authentication and role-based authorization for object access and repair; isolated per-tenant storage; HTTPS for transport; server-side encryption keys outside browser.
- Capture structured correlation IDs, duration and resource metrics; never log plaintext, key bytes or sensitive serialized AAD.
- Benchmark API must not mix wall-time and compute-time or present mock throughput as physical network/storage results.

## UI labels and integrity visualization

- Show Original/Compressed/Encrypted sizes, compression ratio, original-to-end-to-end MiB/s, algorithm, frame count, `polyval_segments`, Rayon threads, tag count, storage replicas, root/generation and verification result.
- Display `parallel_not_exercised` if compressed length yields <=1 POLYVAL segment.
- Display `mock` vs `live` badges/labels for IPFS and ledger distinctly; do not call an internal state machine a deployed smart contract.
- Provide version and repair event timeline; `repair` should not create a new canonical generation.
- For failed decryption/tag mismatch, show safe generic errors, not secret-specific diagnostics.
