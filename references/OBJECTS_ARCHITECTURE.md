# Objects/IPFS/REST/Web sebagai testbed pendukung

Sumber ide platform adalah rancangan terdahulu mengenai `/objects`, self-healing, Merkle membership, tiga replika, ledger, dan dApp. Rancangan ini tidak otomatis membuktikan bahwa implementasi tersebut sudah ada pada repository.

## Komponen konseptual

`API -> Zstd producer -> bounded queue -> AES-GCM-SIV whole-message workflow -> authenticated encrypted object -> encrypted storage/IPFS -> manifest -> integrity registry -> replica registry -> recovery engine -> event ledger -> web UI`.

**Peringatan:** alur di atas konseptual. One-message AES-GCM-SIV memerlukan tag final sebelum ciphertext CTR dapat dihasilkan; arsitektur producer-consumer tidak meniadakan dependensi dua fase tersebut.

## Invariant object

1. Publikasikan objek hanya ketika ciphertext/tag, manifest, dan kebijakan replica telah selesai diverifikasi.
2. Manifest mengikat `object_id`, `generation`, `crypto_algorithm`, `codec_version`, `nonce_metadata`, `encrypted_size`, `content_hash`, `canonical_root`, dan `replica_policy` dalam protokol versi jelas. Jangan menaruh key dalam manifest.
3. CID IPFS dan hash Merkle membuktikan identitas/integritas bytes terhadap root yang dipercaya; **bukan** autentikasi sender sendiri atau kerahasiaan. Nilai canonical root harus dilindungi dari modifikasi/rollback melalui otorisasi dan trust anchor.
4. Proof of inclusion untuk data ≠ proof membership node. Keduanya membutuhkan trust root yang dikelola dengan benar.
5. `repair` menyalin **ciphertext canonical identik** dari sumber sehat dan tidak mengubah generation/root. `version` adalah transaksi generation baru dengan root baru.
6. Tiga replika bukan jaminan pemulihan saat compromise seluruh key/root/ledger. Hindari mengklaim arbitrary Byzantine recovery tanpa threat model dan quorum formal.
7. Gunakan atomic rename/commit, direktori yang dipastikan ada, path traversal validation, bounded upload, cancellation handling, serta restart/recovery idempotent.

## Model state referensi

- Object: `UPLOADING`, `COMMITTED`, `HEALTHY`, `DEGRADED`, `SUSPECT`, `CORRUPTED`, `REPAIRING`, `UNRECOVERABLE`.
- Node: `HEALTHY`, `UNREACHABLE`, `SUSPECT`, `COMPROMISED`, `QUARANTINED`, `REBUILDING`.
- Event: `CORRUPTION_DETECTED`, `NODE_QUARANTINED`, `REPAIR_PROPOSED`, `REPAIR_STARTED`, `REPAIR_VERIFIED`, `REPAIR_COMMITTED`, `ROLLBACK_REJECTED`, `MEMBERSHIP_REJECTED`.

## Negative tests

- Ciphertext bit flip; one missing fragment; tampered manifest; stale generation; fake replica/node; corrupted replica with a healthy replica available; all replicas invalid; interrupted write/rename; permission denied; missing output directory; out-of-order/missing fragment; attacker attempts to propose repair without membership.

Jangan menyebut smart contract atau dApp sungguhan bila implementasinya tidak menggunakan smart contract/ledger terdesentralisasi. Label UI awal: *Storage Integrity & Recovery Console*.
