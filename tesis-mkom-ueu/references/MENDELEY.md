# Panduan Mendeley — Tesis Zstandard / POLYVAL / AES-GCM-SIV

Gunakan panduan ini bersama `LITERATURE.md`, `DOI_LIST.txt`, dan `LITERATURE_MATRIX.csv`.

## Aturan sumber

- Simpan hanya **version of record / final published** sebagai canonical record.
- Jangan gunakan arXiv, IACR ePrint, SSRN, blog, GitHub, whitepaper, atau manuscript under-review sebagai record referensi utama.
- Jika discovery berawal dari preprint, cari versi final dan ganti metadata dengan venue final + DOI.
- RFC/NIST/FIPS ditempatkan pada collection spesifikasi dan **tidak dihitung** sebagai 44 paper akademik.

## Collection yang disarankan

```text
THESIS-ZSTD-AES-GCM-SIV
├── 00_CORE
├── 01_AES_GCM_SIV
├── 02_POLYVAL_GHASH_GF128
├── 03_AEAD_SIV_SECURITY
├── 04_PARALLEL_AUTH
├── 05_ZSTANDARD_ANS_FSE
├── 06_IMPLEMENTATION_BENCHMARK
├── 07_SECURITY_LIMITATIONS
├── 08_USED_IN_PROPOSAL
├── 09_USED_IN_FINAL_THESIS
└── 99_TECHNICAL_SPECS_NOT_COUNTED
```

## Tags

```text
aes-gcm-siv
polyval
ghash
gf2-128
universal-hash
misuse-resistant
siv
aead
zstd
ans
fse
huffman
lz
parallel
segment-composition
math-proof
rust
benchmark
security-bound
pro-cons
read-full
read-partial
used-bab2
used-bab3
used-bab4
```

## Import

1. Ambil DOI dari `DOI_LIST.txt`.
2. Buka DOI pada publisher/final record.
3. Import ke Mendeley Reference Manager dengan Web Importer atau `Add Entry Manually` + DOI lookup.
4. Periksa title, authors, year, venue, volume/issue, pages/article number, dan DOI.
5. Lampirkan PDF legal ke record yang sama; jangan membuat record kedua untuk accepted manuscript/preprint.

## Notes per paper

```text
Problem:
Method:
Mathematical model:
Security model/bound:
Implementation:
Hardware/software environment:
Dataset/workload:
Metrics:
Main result:
PRO:
CONS:
Limitation:
Relation to POLYVAL parallel composition:
Candidate citation for BAB:
```

## IEEE Citation Style

Gunakan Mendeley Cite di Word dan pilih **IEEE**. Nomor `[1]`, `[2]`, dst. mengikuti urutan kemunculan di naskah, bukan nomor `LITERATURE.md`.

## Scopus quality gate UEU

Panduan UEU meminta minimal 30% referensi jurnal terindeks Scopus dalam rentang yang ditentukan. Jangan mengisi `Scopus Verified=YES` hanya karena jurnal terkenal atau mempunyai DOI. Verifikasi di Scopus/akses institusi, kemudian isi kolom `Scopus Verified` pada `LITERATURE_MATRIX.csv`.

## Duplicate rule

Satu karya = satu canonical record final. Contoh yang salah:

```text
AES-GCM-SIV paper - ePrint
AES-GCM-SIV paper - author PDF
AES-GCM-SIV paper - final proceedings
```

Yang benar:

```text
AES-GCM-SIV paper - FINAL PUBLISHED / DOI
  └── legal PDF attachment bila tersedia
```
