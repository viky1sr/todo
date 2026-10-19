# Supporting object storage, CID, Merkle, replication and recovery architecture

This is **engineering context**, not the cryptographic/mathematical thesis contribution. Historic project discussion included Ascon consumer; current thesis crypto is **AES-GCM-SIV** unless an explicitly named separate baseline is requested.

## Storage path

```text
Client -> REST object service -> Zstd producer -> bounded authenticated pipeline
       -> AES-GCM-SIV one-message ciphertext/tag -> durable blob
       -> Merkle/MMR leaves over ciphertext chunks -> signed/authenticated manifest
       -> replica placement -> integrity scanning -> recovery coordinator
       -> UI state view
```

- Object bytes remain off-chain. Ledger/state machine stores hashes, generation, owner/ACL, policy, audit events and optional quorum signatures.
- Merkle inclusion proof means a ciphertext chunk belongs to a specific canonical commitment; it does **not** prove origin without trusted root, nor AEAD decryption validity.
- Node membership proof means storage node is authorized to participate; identity verification and root trust are separate from content proof.
- CID is a content-address identifier (CIDv1 multibase + varint version/codec/multihash). Mock strings labeled CID are not proof of IPFS interoperability; validate structure with `scripts/check_cid.py`, and then test on a real IPFS-compatible node if required.
- For confidentiality, store ciphertext not plaintext; names/lengths/metadata can leak unless separately protected. Key IDs and nonce handling must be bound to manifest with authenticated or signed origin.

## Proposed immutable object record (not confirmed source API)

```
object_id, generation, owner_id, schema_version,
original_size, compressed_size, encrypted_size, codec_config,
aead_algorithm, key_id, nonce, aad_schema_version,
merkle_root, encrypted_blob_digest, replica_policy,
commit_timestamp, state
```

A `generation` identifies the canonical encrypted bytes for that version. Replication copies the exact encrypted bytes, not re-encryption (which changes tag, nonce context, digest and root). Key rotation is a **new encrypted generation** with associated metadata and secure migration.

## State transitions

Objects: `UPLOADING -> COMMITTED -> HEALTHY -> {DEGRADED,SUSPECT,CORRUPTED} -> REPAIRING -> HEALTHY` or `UNRECOVERABLE` based on policy. Nodes: `HEALTHY,UNREACHABLE,SUSPECT,COMPROMISED,QUARANTINED,REBUILDING`.

Events are append-only, with actor identity, object generation, evidence hash, event ID, timestamps. A Rust append-only event log is **not automatically a decentralized blockchain or smart contract**; call UI "Storage Integrity & Recovery Console" unless real distributed ledger contract exists.

## Defensive repair algorithm

1. Verify committed manifest authenticity and trusted canonical root/generation.
2. Inspect replicas; detect missing, outdated, tampered or unreachable states. Do not trust self-reported node health.
3. Quarantine suspect nodes where indicated; authorize repair using signed policy and least privilege.
4. Select healthy source replica meeting canonical ciphertext hash and data-membership proof; consider quorum policy against malicious mirrors.
5. Copy encrypted chunks to healthy target, verify chunk digests + Merkle inclusion and final blob digest. Verify AEAD where key authority and threat model allow.
6. Commit replica status only after durable write and verification; record append-only audit event.
7. Keep **same canonical root for byte-identical repair**. `repair != versioning`: new object/upload or re-encryption with fresh nonce requires new generation/root.

## Threat events and response

| Threat | Detect | Defensive action |
|---|---|---|
| changed ciphertext chunk | Merkle leaf/hash mismatch | isolate replica, verify canonical, repair from verified source |
| deleted object/replica | missing record/blob | restore if valid replica still exists |
| stale or rollback generation | manifest generation mismatch | reject, fetch canonical committed generation |
| malicious node impersonation | invalid membership/signature | reject ACK/repair/vote |
| compromised datacenter | correlated invalid proofs / security signals | quarantine and reschedule replicas |
| corrupted manifest | signature/root mismatch | quarantine, recover canonical metadata |
| wrong key/AAD/nonce | tag verification failure | reject, inspect credentials and metadata |
| partial-write crash | missing COMMITTED atomically | garbage collect uncommitted temp state |
| key exposure | security alert, forensic evidence | rotate via new generation, revoke old permissions |

## Important caveats

- Three replicas improve availability, not guarantee survival against a shared admin key or common-mode event. Validate failure domains (DC, account, region, credentials).
- Hash/Merkle root is meaningful only with a trusted authenticated canonical root; attacker who controls canonical root can recompute proof.
- An `IPFS roundtrip: OK` for an in-memory map does not validate interoperability or correct CID. In prior log, `bafybeigf7b969b0912a860600000073` is not valid Base32 CIDv1: it includes `0`, `1`, `8`, `9`.

See CID specification: https://specs.ipfs.tech/cid/ ; Content-addressing docs: https://docs.ipfs.tech/concepts/content-addressing/ .

## Implemented in `crates/ipfs` (`todo-ipfs`)

- `cid`: strict CIDv0/CIDv1 + multihash + multicodec (base32 `b`/`B`, base58btc `z`/`Qm`), canonical varints, sha2-256 verification. Legacy mock strings such as `bafybeigf7b969b0912a860600000073` are rejected.
- `block`/`BlockStore`: backends are untrusted; every `get_block` re-hashes bytes against the CID; blocks ≤ 1 MiB, default chunk 256 KiB.
- `manifest`: canonical DAG-JSON object manifest (`todo-ipfs/object-manifest/v1`); its CID is the object root and trust anchor. Kubo traverses its links (`refs -r`, recursive pin).
- `object::ObjectStore`: chunk → raw blocks → manifest → recursive pin; reads verify every block, sizes and `max_object_size`.
- Backends: `KuboRpcClient` (live, Kubo RPC `/api/v0/*`, local-only reads by default), `TrustlessGateway` (live, read-only, `?format=raw`), `MemoryBlockStore` (**MOCK**, real CIDs, fault injection).
- `replica::ReplicaSet`: audit (`healthy/missing/corrupted/unreachable`) and byte-identical repair from CID-verified copies with read-back verification; never reports recovery without a verified source.
- REST: `TODO_IPFS_BACKEND=mock|kubo|gateway`, `TODO_IPFS_URL`; `POST /api/v1/ipfs/publish` returns `root_cid` and `backend`; `POST /api/v1/ipfs/fetch` verifies CIDs, then the AEAD tag.
- Live tests: `TODO_IPFS_KUBO_API=… [TODO_IPFS_GATEWAY=…] cargo test -p todo-ipfs --test live_kubo -- --ignored --test-threads=1` (use a disposable node).

Not implemented: an IPFS node itself (libp2p, Bitswap, DHT), UnixFS/dag-pb files, IPNS, pinning-service API, signed manifests, and node membership/authorization.
