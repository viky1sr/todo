# Profil dan Scope Penelitian Aktif

## Judul

**Komposisi Paralel POLYVAL pada Segmen Zstandard untuk AES-GCM-SIV**

Judul berada di bawah batas 16 kata UEU dan tidak memuat objek instansi, lokasi, atau tahun penelitian.

## Abstrak kerja dari pengguna

Integrasi antara kompresi data dan enkripsi terautentikasi sangat penting dalam sistem berkinerja tinggi. Penelitian ini mengusulkan komposisi paralel fungsi hash POLYVAL pada segmen data hasil kompresi Zstandard yang dienkripsi menggunakan skema AES-GCM-SIV. Meskipun skema *nonce-misuse resistant* seperti AES-GCM-SIV menawarkan keamanan operasional yang superior, komputasi autentikasi pada data berukuran masif seringkali menimbulkan *bottleneck* kinerja. Dengan membagi aliran data kompresi Zstandard ke dalam segmen-segmen independen, proses komputasi POLYVAL dapat didistribusikan secara paralel. Penelitian ini berfokus pada dua aspek utama: pertama, pembuktian kesetaraan hasil matematis (ekuivalensi *tag* autentikasi) antara pemrosesan polinomial secara sekuensial dan paralel; kedua, evaluasi pengaruh segmentasi ini terhadap kinerja sistem secara keseluruhan. Melalui pengujian implementasi, kinerja sistem diukur berdasarkan metrik *throughput* dan latensi komputasi untuk memvalidasi bahwa optimasi komposisi paralel ini mampu memberikan akselerasi kinerja tanpa mengorbankan integritas maupun kerahasiaan kriptografis.

**Catatan quality gate:** abstrak kerja ini sekitar 131 kata, sedangkan panduan UEU pada skill menetapkan 200–250 kata. Jangan menyebutnya abstrak final sebelum diperluas. Hindari pula mengklaim “mampu memberikan akselerasi” sebagai hasil sebelum eksperimen selesai; pada proposal gunakan bahasa hipotesis seperti “menilai apakah” atau “mengevaluasi potensi”.

## Fokus ilmiah

Penelitian bukan membuat cipher baru dan bukan mengubah Zstandard. Kontribusi yang diuji adalah **komposisi paralel POLYVAL** atas byte stream hasil kompresi Zstandard sambil menjaga hasil autentikasi identik dengan pemrosesan AES-GCM-SIV standar untuk input yang sama.

Pipeline utama:

```text
input
  -> Zstandard compression
  -> compressed byte stream
  -> pembentukan input POLYVAL sesuai RFC 8452
  -> segmentasi untuk penelitian
  -> POLYVAL per segmen secara paralel
  -> komposisi state/hash
  -> tag AES-GCM-SIV standar
  -> AES-CTR phase AES-GCM-SIV
```

## Batas penting AES-GCM-SIV

AES-GCM-SIV secara standar bukan skema satu-pass penuh. Tag/SIV dihitung dari POLYVAL sebelum fase counter-mode mengenkripsi plaintext terkompresi. Karena itu, penelitian hanya boleh mengklaim **memparalelkan fase POLYVAL/authentication**, bukan menghilangkan sifat dua lintasan AES-GCM-SIV.

## Definisi “segmen Zstandard”

Gunakan istilah **segmen penelitian** untuk potongan dari **compressed byte stream** yang menjadi input POLYVAL. Jangan mengklaim `segment` sebagai struktur resmi format Zstandard.

Eksperimen utama harus menjaga satu hasil kompresi yang sama antara baseline dan proposed method:

```text
C = Zstd(M)
```

Kemudian hanya hashing `C` yang disegmentasi. Dengan begitu, perubahan throughput dapat diatribusikan ke POLYVAL parallel composition, bukan ke perubahan compression ratio.

Eksperimen dengan beberapa independent Zstd frames boleh dilakukan sebagai eksperimen sekunder, tetapi hasilnya tidak boleh dicampur dengan eksperimen utama karena byte stream dan compression ratio berubah.

## Model matematis POLYVAL

Untuk blok 128-bit `X_1, ..., X_n` dan hash key `H`, gunakan recurrence abstrak:

```text
S_0 = 0
S_i = (S_{i-1} xor X_i) * H
```

operasi perkalian dilakukan pada field yang ditetapkan POLYVAL.

Untuk dua urutan blok `A` dan `B`, jika `B` memiliki `n_B` blok dan masing-masing hash dimulai dari nol, bentuk komposisi yang harus dibuktikan adalah:

```text
P(A || B) = P(A) * H^(n_B) xor P(B)
```

Representasikan hasil segmen sebagai pasangan:

```text
Sigma = (P, n)
```

dan operator komposisi:

```text
(P_A, n_A) otimes (P_B, n_B)
  = (P_A * H^(n_B) xor P_B, n_A + n_B)
```

Target formal:

1. buktikan operator `otimes` asosiatif;
2. buktikan hasil reduction tree identik dengan POLYVAL sekuensial;
3. buktikan tag AES-GCM-SIV identik untuk `key`, `nonce`, `AAD`, dan compressed plaintext yang sama;
4. validasi implementasi terhadap RFC 8452 test vectors dan implementasi referensi.

### Boundary rule

Jangan melakukan zero-padding independen pada setiap segmen arbitrer karena dapat mengubah message yang di-hash. Untuk scope utama, buat boundary segmen pada **kelipatan 16 byte** dari POLYVAL block stream setelah layout input RFC 8452 dibentuk. Hanya final block yang mengikuti padding standar. Jika ingin mendukung boundary arbitrer, state komposisi harus membawa residual byte secara eksplisit dan dibuktikan terpisah.

## Research gap yang aman

Jangan menulis “parallel polynomial authentication belum pernah ada”; literatur GHASH/GCM telah memiliki penelitian paralel dan pipelined.

Gap yang layak diuji:

> Literatur telah menunjukkan paralelisasi polynomial authentication pada GCM/GHASH dan telah membangun AES-GCM-SIV dengan POLYVAL untuk nonce-misuse resistance. Namun, perlu diuji secara khusus bagaimana komposisi paralel POLYVAL diterapkan pada compressed byte stream Zstandard dengan pembuktian ekuivalensi tag terhadap AES-GCM-SIV standar, serta bagaimana segment size dan worker count memengaruhi throughput dan latency end-to-end tanpa mengubah compressed representation.

Formulasi ini wajib diuji ulang terhadap corpus `LITERATURE.md` sebelum proposal final.

## Baseline dan proposed method

Baseline utama:

```text
Zstd(M) -> sequential POLYVAL -> AES-GCM-SIV
```

Proposed:

```text
Zstd(M)
 -> fixed compressed stream C
 -> split POLYVAL block stream into N segments
 -> parallel local POLYVAL
 -> associative composition
 -> standard AES-GCM-SIV tag/counter phase
```

Implementasikan prototype di **Rust**. Rust adalah bahasa eksperimen, bukan novelty ilmiah.

## Metrik eksperimen

Wajib ukur:
- correctness byte-for-byte dan tag equivalence;
- throughput MiB/s;
- total latency;
- waktu fase POLYVAL;
- scaling terhadap worker count;
- sensitivity terhadap segment size;
- CPU utilization/cycles-per-byte bila tersedia;
- peak memory dan memory traffic bila dapat diukur andal;
- compression ratio dan compressed size sebagai kontrol (harus sama pada eksperimen utama);
- overhead precomputation `H^k` dan reduction/composition.

Laporkan PRO dan CONS. Hasil yang menunjukkan speedup hanya pada ukuran data/worker tertentu tetap merupakan hasil penelitian yang valid.

## PRO/CONS yang harus diuji, bukan diasumsikan

Potensi PRO:
- mengurangi critical path POLYVAL pada data besar;
- memanfaatkan multi-core/SIMD;
- mempertahankan tag standar jika komposisi benar;
- tidak mengubah compressed byte stream pada eksperimen utama.

Potensi CONS:
- overhead segment scheduling dan reduction;
- precomputation powers of `H`;
- speedup dapat hilang pada pesan kecil;
- memory bandwidth dapat menjadi bottleneck;
- AES-GCM-SIV tetap membutuhkan fase enkripsi setelah tag/SIV tersedia;
- segmentasi independent Zstd frame dapat menurunkan compression ratio jika dipakai.

## Implementasi dan validasi Rust

1. Gunakan implementasi baseline yang mengikuti RFC 8452.
2. Implementasikan POLYVAL sekuensial sendiri sebagai oracle internal yang diuji terhadap test vector/reference library.
3. Implementasikan local segment hash dan composition operator.
4. Uji property-based/randomized equality: `parallel == sequential` untuk banyak panjang data, AAD, segment size, dan worker count.
5. Uji edge cases: empty AAD, empty message, final partial block, satu segmen, banyak segmen, ukuran tepat kelipatan 16, dan data sangat besar.
6. Benchmark release build, pin versi compiler/dependencies, dokumentasikan CPU, core/thread count, memory, OS, dan flags.
7. Pisahkan waktu Zstd, POLYVAL, composition, dan AES counter phase agar sumber speedup dapat dijelaskan.
