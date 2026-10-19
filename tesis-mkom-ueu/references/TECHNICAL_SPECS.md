# Technical Specifications — Tidak Dihitung sebagai Referensi Akademik Utama

Dokumen berikut digunakan untuk definisi algoritma, interoperabilitas, test vector, dan implementasi. **Jangan menghitungnya ke dalam 44 paper peer-reviewed di `LITERATURE.md`.**

| Spesifikasi | Fungsi dalam tesis | URL resmi |
|---|---|---|
| RFC 8452 — AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption | Spesifikasi AES-GCM-SIV, POLYVAL, key derivation, tag generation, counter mode, dan test vectors. | https://www.rfc-editor.org/rfc/rfc8452.html |
| RFC 8878 — Zstandard Compression and the application/zstd Media Type | Spesifikasi format Zstandard, blocks, literals, sequences, Huffman/FSE decoding. | https://www.rfc-editor.org/rfc/rfc8878.html |
| RFC 9659 — Window Sizing for Zstandard Compression | Referensi teknis untuk window sizing Zstd bila eksperimen menyentuh parameter window. | https://www.rfc-editor.org/rfc/rfc9659.html |
| NIST SP 800-38D — GCM and GMAC | Spesifikasi GCM/GHASH untuk pembanding teknis. | https://csrc.nist.gov/pubs/sp/800/38/d/final |
| FIPS 197 — Advanced Encryption Standard (AES) | Definisi AES yang digunakan sebagai block cipher. | https://csrc.nist.gov/pubs/fips/197/final |

Aturan:
- RFC/NIST/FIPS boleh disitasi untuk spesifikasi, parameter, test vector, dan definisi implementasi.
- Jangan gunakan dokumen spesifikasi sebagai satu-satunya dasar `research gap`.
- Research gap dan state of the art harus ditopang paper final peer-reviewed pada `LITERATURE.md`.
