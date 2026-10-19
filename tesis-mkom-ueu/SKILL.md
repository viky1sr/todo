---
name: tesis-mkom-ueu
description: Panduan penyusunan Proposal Tesis, Tesis Final, dan Artikel Ilmiah MKom Universitas Esa Unggul berdasarkan Pedoman 2026, termasuk penelitian aktif tentang komposisi paralel POLYVAL pada hasil kompresi Zstandard untuk AES-GCM-SIV, pembuktian matematis, implementasi Rust, benchmark, literature review, research gap, IEEE citation, dan Mendeley. Gunakan saat pengguna menyusun, merevisi, memformat, memvalidasi, atau meneliti tesis MKom UEU.
---

# Tesis MKom Universitas Esa Unggul (UEU)

Skill ini memberikan panduan dan bantuan terstruktur dalam penyusunan naskah Proposal Tesis, Tesis Final, serta Artikel Publikasi Ilmiah sesuai standar akademik Fakultas Ilmu Komputer Universitas Esa Unggul Tahun 2026[cite: 1].

## When to Use

Gunakan skill ini ketika pengguna:
- Meminta penyusunan draf Proposal Tesis, Tesis Final, atau Artikel Publikasi Ilmiah MKom UEU[cite: 1, 6].
- Meminta aturan format fisik, margin, tipografi, penomoran halaman, atau struktur bab naskah[cite: 7, 8, 9, 12].
- Memerlukan pemeriksaan kelengkapan bab (BAB I s/d BAB V) atau bagian awal/akhir (Abstrak, Lembar Pengesahan, Referensi IEEE)[cite: 7, 8, 9, 10].
- Mengonfirmasi kepatuhan aturan khusus seperti batasan judul (maksimal 16 kata), batas kata abstrak, dan rasio sitasi jurnal Scopus[cite: 7, 8, 10].

## Standard Rules & Formatting Constraints

### 1. Spesifikasi Fisik & Tipografi Naskah
- **Kertas**: A4 ($21\text{ cm} \times 29.7\text{ cm}$), HVS 70 gram, warna putih polos[cite: 11].
- **Batas Margin Teks**:
  - Batas Kiri: 4 cm (termasuk 1 cm untuk jilid)[cite: 12].
  - Batas Kanan: 3 cm[cite: 12].
  - Batas Atas: 3 cm[cite: 12].
  - Batas Bawah: 3 cm[cite: 12].
- **Format Teks Utama**:
  - Jenis & Ukuran Huruf: **Times New Roman 12 pt**[cite: 12].
  - Spasi Paragraf: **1,15** (Ms. Word: *Before* = 0 pt, *After* = 0 pt)[cite: 12].
  - Pengaturan Rata Teks: **Rata Kiri dan Rata Kanan (Justify)**[cite: 12].
- **Header Atas (Running Header)**:
  - Teks: **Universitas Esa Unggul**[cite: 12]
  - Format: **Arial 10 pt Cetak Tebal (Bold)**, Posisi Kanan Atas[cite: 12].
  - Berlaku mulai dari halaman Abstrak hingga Daftar Referensi[cite: 12].
- **Penomoran Halaman**:
  - Jenis Huruf: Times New Roman 12 pt, Posisi Tengah Bawah (2 cm dari tepi kertas)[cite: 12].
  - Bagian Awal: Angka Romawi kecil (`i, ii, iii, ...`). Halaman Judul dihitung tetapi nomor tidak dicetak[cite: 12].
  - Bagian Isi & Akhir: Angka Latin (`1, 2, 3, ...`)[cite: 12].

### 2. Aturan Sampul & Judul Tesis
- **Warna Sampul Hardcover**: Warna Hitam (Komposisi: $C=93, M=88, Y=89, K=90$) dengan Tulisan & Logo Tinta Emas[cite: 11].
- **Logo UEU**: Diameter 3 cm (simetris di tengah)[cite: 11].
- **Judul Tesis**:
  - Maksimal **16 kata** (tidak termasuk preposisi/kata depan)[cite: 7, 11].
  - **Dilarang menyebutkan objek lokasi/waktu penelitian** (contoh: *tidak boleh mencantumkan "pada PT XYZ Tahun 2026"*)[cite: 7, 11].
- **Punggung Sampul (Spine)**:
  - Huruf KAPITAL, Times New Roman 8 pt Bold, Spasi 1, Rata Tengah[cite: 11].
  - Urutan: `TESIS | NAMA & NIM | JUDUL TESIS | TAHUN`[cite: 11, 12].

### 3. Ketentuan Referensi & Sitasi
- **Gaya Sitasi**: IEEE Citation Style (`[1]`, `[2]`)[cite: 10, 33].
- **Jumlah Minimal**: Sekurang-kurangnya **30 referensi utama**[cite: 29].
- **Kuota Scopus**: Minimal **30% dari total referensi** berasal dari artikel jurnal terindeks Scopus terbitan 5–10 tahun terakhir[cite: 10, 29].

---

## Document Structure & Layout

### A. Bagian Awal (Front Matter)
1. **Halaman Sampul & Halaman Judul**[cite: 7]
2. **Halaman Pernyataan Keaslian**[cite: 7]
3. **Halaman Pengesahan** (Memuat TTD Tim Penguji & Ketua Program Studi)[cite: 7, 8, 19]
4. **Ucapan Terima Kasih / Kata Pengantar**[cite: 8]
5. **Halaman Pernyataan Persetujuan Publikasi Akademis**[cite: 8]
6. **Abstrak (Bahasa Indonesia & Bahasa Inggris)**:
   - Panjang 200–250 kata, disusun tepat dalam 1 (satu) paragraf[cite: 8].
   - Dilengkapi Kata Kunci / Key words (3–5 kata/frasa)[cite: 8].
7. **Daftar Isi, Daftar Tabel, Daftar Gambar, Daftar Rumus, Daftar Lampiran**:
   - Penomoran Bab: Angka Romawi Besar (`BAB I`, `BAB II`)[cite: 9].
   - Penomoran Sub-bab: Angka Latin maksimal 3 tingkat (`1.1`, `1.1.1`)[cite: 9].

### B. Bagian Isi (Main Body)

#### Proposal Tesis (3 BAB)
- **BAB I PENDAHULUAN**: Latar Belakang, Rumusan Masalah, Tujuan Penelitian, Manfaat Penelitian, Batasan Masalah, dan Kontribusi Ilmiah[cite: 9].
- **BAB II TINJAUAN PUSTAKA**: Landasan Teori, Penelitian Terdahulu, *State of the Art*, *Research Gap*, dan Sintesis Kritis[cite: 9].
- **BAB III METODE PENELITIAN**: Pendekatan Penelitian, Objek/Dataset, Definisi Operasional Variabel, Alat & Bahan/Lingkungan Komputasi, Tahapan Penelitian, Teknik Pengumpulan & Analisis Data, Metrik Evaluasi, serta Validitas, Reliabilitas, & Reproduksibilitas[cite: 9, 30].

#### Tesis Final (5 BAB)
Merupakan pengembangan dari Proposal Tesis dengan tambahan:
- **BAB IV HASIL DAN PEMBAHASAN**: Paparan Hasil Penelitian, Analisis, Perbandingan dengan *State of the Art* / Baseline, Keterbatasan Penelitian, dan Etika Teknologi (Pertimbangan Etis, Tanggung Jawab, Dampak Sosial)[cite: 9, 10].
- **BAB V KESIMPULAN DAN SARAN**: Kesimpulan (menjawab langsung rumusan masalah/tujuan) dan Saran Penelitian Lanjutan[cite: 10, 32].

### C. Bagian Akhir (Back Matter)
- **Daftar Referensi**: Disusun sesuai standar IEEE[cite: 10, 33].
- **Lampiran**: Pelengkap penelitian (dataset, kode program, arsitektur sistem, jadwal)[cite: 10].

### D. Artikel Publikasi Ilmiah
- Disusun sesuai template jurnal target (minimal terindeks Sinta 3)[cite: 10].
- Komponen wajib: Abstrak (200–250 kata), Pendahuluan (*Latar Belakang, Research Gap, Rumusan, Tujuan, Kontribusi*), Metode, Hasil dan Pembahasan, Kesimpulan, dan Daftar Pustaka[cite: 10].

---

## Guidelines & Gotchas for Generation

1. **Aturan Judul Tesis**: Pastikan judul tidak mencantumkan nama instansi/organisasi spesifik, lokasi geografis, maupun tahun pelaksanaan penelitian[cite: 7, 11].
2. **Integritas Akademik & AI Generatif**: AI dapat digunakan sebagai alat bantu akademik terbatas (pengeditan bahasa/struktur), tetapi **dilarang keras** memfabrikasi data, memalsukan hasil, atau menggantikan pemikiran kritis ilmiah[cite: 5, 28].
3. **Format Sitasi IEEE**: Nomor rujukan pada teks ditulis berurutan sesuai kemunculannya `[1]`, `[2]`, `[3]`, dan dicocokkan secara tepat di Daftar Referensi[cite: 10, 33].
4. **Header Halaman**: Ingat untuk selalu menyertakan header `Universitas Esa Unggul` (Arial 10 pt Bold) di posisi kanan atas pada setiap halaman mulai dari Abstrak hingga Daftar Referensi[cite: 12].

---

## Research Evidence Workflow — Topik Aktif

Gunakan resource berikut secara progresif:

- `references/RESEARCH_SCOPE.md` untuk judul, abstrak kerja, scope, model matematis, research gap, baseline, implementasi Rust, dan metrik eksperimen.
- `references/LITERATURE.md` untuk corpus **44 paper final peer-reviewed**.
- `references/LITERATURE_MATRIX.csv` untuk sintesis paper dan pencatatan PRO/CONS/gap.
- `references/MENDELEY.md` untuk pengelolaan canonical record dan sitasi IEEE.
- `references/TECHNICAL_SPECS.md` untuk RFC/NIST/FIPS yang hanya berfungsi sebagai spesifikasi teknis.
- `references/DOI_LIST.txt` untuk import/verifikasi DOI.

### Aturan referensi wajib

1. Gunakan hanya versi **final published** pada jurnal atau conference proceedings akademik peer-reviewed untuk corpus utama.
2. Jangan gunakan atau menyitasi arXiv, IACR ePrint, SSRN, blog, GitHub, preprint server, whitepaper vendor, atau manuscript *under review* sebagai referensi akademik utama.
3. Jika sebuah ide ditemukan melalui preprint, cari versi finalnya. Hanya gunakan final venue/DOI dalam literature matrix dan daftar pustaka.
4. Pertahankan 30–68 referensi akademik utama; corpus bawaan memiliki 44 referensi.
5. DOI membuktikan persistent identifier, bukan otomatis Scopus. Verifikasi status Scopus secara terpisah sebelum memenuhi kuota UEU.
6. RFC/NIST/FIPS boleh dipakai untuk definisi algoritma, test vector, dan interoperabilitas; jangan hitung sebagai paper peer-reviewed dan jangan jadikan sumber tunggal research gap.
7. Jangan menyatakan “belum pernah ada penelitian” tanpa systematic search. Nyatakan gap sebagai keterbatasan spesifik yang didukung corpus.
8. Bedakan bukti formal dari bukti empiris. Ekuivalensi hash/tag dibuktikan matematis dan diuji; throughput/latency dibuktikan melalui eksperimen.

### Judul penelitian aktif

**Komposisi Paralel POLYVAL pada Segmen Zstandard untuk AES-GCM-SIV**

Jangan mengganti AES-GCM-SIV dengan cipher lain kecuali pengguna meminta perubahan eksplisit.

### Core research claim yang diperbolehkan

Fokuskan penelitian pada komposisi paralel POLYVAL atas compressed byte stream Zstandard dengan target:

- hasil POLYVAL paralel identik dengan sekuensial;
- tag AES-GCM-SIV identik untuk input/key/nonce/AAD yang sama;
- compressed representation sama pada baseline dan eksperimen utama;
- evaluasi throughput/latency menunjukkan kapan parallel composition menguntungkan atau merugikan.

Jangan mengklaim bahwa AES-GCM-SIV menjadi one-pass. AES-GCM-SIV standar tetap membutuhkan tag/SIV sebelum counter-mode encryption. Jangan mengklaim “segmen” sebagai struktur resmi Zstandard; gunakan istilah **segmen penelitian** kecuali eksperimen memang memakai Zstd frames/blocks/jobs yang didefinisikan jelas.

### Mathematical proof gate

Gunakan recurrence POLYVAL dan operator komposisi pada `RESEARCH_SCOPE.md`. Wajib buktikan:

- ekuivalensi concatenation;
- asosiativitas operator composition;
- equivalence sequential vs tree reduction;
- tag equivalence terhadap AES-GCM-SIV standar;
- aturan boundary/padding 16-byte agar segmentasi tidak mengubah hashed message.

Jangan melakukan independent zero-padding untuk setiap segmen karena akan menghasilkan input POLYVAL yang berbeda.

### Implementation gate

Implementasikan prototype dalam Rust dan validasi terhadap RFC 8452 test vectors serta implementasi referensi. Pisahkan benchmark minimal menjadi `Zstd`, `POLYVAL`, `composition`, dan `AES counter phase` agar sumber speedup dapat dijelaskan. Gunakan release build dan dokumentasikan hardware, OS, compiler, crate versions, worker count, segment size, dan dataset.

### Scientific reporting gate

Setiap hasil wajib memuat PRO, CONS, limitation, dan kondisi ketika metode tidak memberi manfaat. Jangan mengubah hipotesis menjadi klaim hasil sebelum data eksperimen tersedia.

