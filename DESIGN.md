# Desain Comick MCP

## Tujuan dan batas

Membantu percakapan untuk mencari manga/manhwa/manhua, membandingkan judul, dan memberi rekomendasi berdasarkan metadata. Server mengambil dan merapikan data; alasan serta urutan rekomendasi tetap dibuat di chat, bukan diklaim sebagai skor kemiripan API.

Pertahankan server lokal `stdio`, SDK MCP dan Zod yang sudah terpasang, serta pembagian tiga file: `index.ts` untuk tool, `catalog.ts` untuk katalog/normalisasi, dan `oauth.ts` untuk akun/token. Tidak perlu database, embedding, scheduler, transport HTTP, atau framework tambahan.

## Sumber resmi

- [Panduan Comick](https://comick.dev/docs)
- [Catalog API explorer](https://api.comick.dev/docs/) dan [OpenAPI katalog](https://api.comick.dev/docs/json)
- [OAuth](https://comick.dev/docs/oauth)
- [Refresh dan disconnect](https://comick.dev/docs/refresh-and-disconnect)
- [Library](https://comick.dev/docs/library) dan [OpenAPI library](https://comick.dev/docs/openapi.json)
- [Error dan limit](https://comick.dev/docs/errors)
- [MCP tools, structured content, output schema, dan error](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP stdio](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

OpenAPI yang diperiksa: katalog versi `1.1`, library versi `1.1.0`. Spesifikasi MCP yang dirujuk: `2025-11-25`; ini bukan klaim bahwa tidak ada versi lebih baru. Dokumen dan sampel publik dipakai untuk desain; endpoint akun belum diuji dengan kredensial pengguna.

## Temuan dari API publik

Permintaan anonim search, genre, dan detail untuk Solo Leveling berhasil menerima JSON melalui tool download pada sesi riset ini. Keberhasilan ini tidak menjamin rute yang sama selalu lolos infrastruktur akses.

- Search mengembalikan array tanpa total. Dua hasil sampel berukuran sekitar 10 KB; detail satu judul sekitar 195 KB. Mengembalikan respons mentah membuang konteks chat.
- `genres` pada search adalah ID angka. `/genre/` menyediakan `id`, `name`, `slug`, dan `group`; gunakan tabel ini, bukan pemetaan angka buatan.
- Rating publik dapat berupa string, misalnya `bayesian_rating: "9.19"`; normalisasi menjadi angka finite atau `null`, bukan `0` untuk nilai kosong.
- Judul utama detail bisa berbeda dari judul tampilan. Sampel `comic.title` bukan “Solo Leveling”, tetapi `md_titles` berbahasa Inggris dengan `is_default: true` berisi judul tersebut.
- Detail menyertakan banyak data yang tidak dibutuhkan: ulasan, identitas kontributor, HTML, dan metadata internal. Gunakan allowlist field output.
- Detail memuat rekomendasi komunitas. Vote komunitas bukan skor kemiripan personal.
- `/integrations/v1/titles/{hid}` adalah detail resmi melalui OAuth `library:read`, dengan sinopsis dan metadata tracker tetapi tanpa genre/tag pada schema saat ini.
- `violence_rating` mendukung `none` dan `graphic`, terpisah dari `content_rating`. Sampel bertag `gore` masih memiliki `violence_rating: none`; jangan menjanjikan klasifikasi sempurna atau menyimpulkan aman dari satu field.

## Kontrak tool

| Tool | Input dan perilaku | Akses |
| --- | --- | --- |
| `comick_search` | Filter yang sudah ada, satu halaman; output ringkas dengan genre terbaca. Default tetap 15, maksimum lokal tetap 50 agar respons terkendali. | Publik |
| `comick_title` | Pertahankan `slug` dan `media_type`; tambah `hid` opsional untuk fallback yang identitasnya pasti. `slug` tetap boleh berisi HID sesuai API. | Publik; fallback OAuth hanya bila sudah terhubung |
| `comick_filters` | `kind: genres | tags`; kembalikan nama, slug, dan grup bila tersedia, bukan statistik jumlah pemakaian. | Publik |
| `comick_connect` | `action: start | status`, `open_browser`; OAuth PKCE yang sudah ada. Tidak pernah login otomatis akibat pencarian. | Akun |
| `comick_disconnect` | Objek input kosong; revoke token yang tersimpan, lalu hapus dari OS credential store. | Akun |
| `comick_me` | Profil publik akun terhubung yang sudah ada. | `library:read` |
| `comick_library` | Pagination cursor yang sudah ada; pertahankan cursor dan filter tanpa modifikasi. | `library:read` |

Tahap berikutnya, bukan bagian implementasi awal:

- `comick_library_entry({hid})`: `GET /me/library/{hid}`. Satu entry tanpa scan semua halaman; `404` berarti entry tidak ditemukan, bukan bukti pasti judul belum di-follow jika judulnya sendiri belum tervalidasi.
- `comick_chapters({hid, lang?, page?, limit?})`: `GET /v1.0/comic/{hid}/chapters`, default 12. Gunakan HID judul, bukan HID chapter. Jika menjanjikan “rilis terbaru”, gunakan `date-order=0`; urutan nomor chapter dan tanggal rilis tidak selalu sama.
- Filter `violence_rating` dan `excluded_violence_rating` pada search, masing-masing enum `none | graphic` dengan array maksimal dua nilai. Exclusion menang menurut dokumentasi API.
- Write tool hanya setelah ada kebutuhan tracking, pengaturan app yang sesuai, dan consent baru `library:write`. Jangan memperluas scope saat ini.

## Output ringkas

Search mengembalikan objek `{items, page, limit, returned_count, warnings}`. Tidak membuat `total`, `total_pages`, atau `has_more` yang tidak diberikan upstream; pengguna boleh meminta halaman berikutnya, tetapi keyword search bukan ekspor katalog lengkap.

Setiap item berisi:

- `hid`, `slug`, `title`, `media_type`, `url`.
- `synopsis`: potongan paragraf pembuka deskripsi, maksimum 600 karakter secara default. Ini kutipan yang dipangkas, bukan ringkasan semantik buatan server. Sertakan `synopsis_truncated`.
- `genres`: array `{name, slug, group}` dari pemetaan resmi; `unresolved_genre_ids` bila ada ID yang belum dikenal.
- `rating`: `{site_score, rating_count}`; jangan campur dengan rating milik pengguna di library.
- `publication_status`: `{code, name}` atau `null`; pisahkan `translation_completed`.
- `country`, `year`, `last_released_number`, `content_rating`, `violence_rating` bila tersedia; field yang tidak diketahui menjadi `null`, bukan tebakan.

Detail memakai bentuk inti yang sama dengan deskripsi lebih panjang (batas 4.000 karakter), judul alternatif terpilih, author/artist, bahasa tersedia, tag, dan maksimal lima rekomendasi komunitas bila tersedia. Field tidak tersedia tetap ditandai. Nilai batas ini ditulis langsung di schema agar jelas dan dapat disesuaikan, bukan dibuat sistem konfigurasi baru.

Preferensi judul tampilan: judul Inggris default dari upstream, lalu judul default lainnya, lalu judul utama upstream. Jangan menerjemahkan sendiri atau membuang alias asli yang relevan.

Gunakan schema Zod untuk validasi bentuk upstream yang dipakai dan `outputSchema` tool. Normalisasi hanya field yang dipakai; field tambahan upstream diabaikan. Field identitas yang rusak menghasilkan `invalid_response`, bukan item hasil tebakan. Genre lookup yang gagal tidak menggagalkan hasil search yang valid: hasil tetap ada dengan warning dan ID yang belum terselesaikan.

Sukses mengirim objek yang sama dalam `structuredContent` dan JSON `content` teks sesuai rekomendasi kompatibilitas MCP. Error eksekusi menggunakan `isError: true`, kode error stabil dan pesan aman. Jangan menempelkan exception subprocess atau body HTML upstream.

## Fallback detail tanpa cache lokal

1. Coba endpoint detail publik memakai identifier yang diminta.
2. Fallback hanya untuk `403` atau respons HTML/non-JSON yang menunjukkan jalur detail tidak dapat dipakai. `404`, `429`, dan `5xx` tidak disamarkan sebagai detail sukses.
3. Bila ada HID yang diketahui dan akun sudah terhubung, coba `GET /integrations/v1/titles/{hid}`. Jangan membuka browser atau meminta consent diam-diam. Jangan kirim token ke endpoint katalog publik.
4. Jika belum ada data alternatif, lakukan maksimal satu search publik menggunakan identifier. Ambil hanya hasil yang HID atau slug-nya cocok persis, termasuk media type. Jangan menerima kandidat pertama hanya karena judul mirip; slug belum tentu cocok sebagai keyword search.
5. Bila tidak ada kecocokan identitas pasti, kembalikan error akses dengan saran memakai `comick_search`; jangan mengarang detail dan jangan mengulang pencarian tanpa batas.
6. Bila fallback berhasil, hasil memuat `partial: true`, `source: oauth_title | search`, `missing_fields`, dan warning penyebab fallback. Hasil normal memakai `source: catalog_detail` dan `partial: false` untuk menandai jalur normal, bukan jaminan semua field berisi nilai.

Fallback OAuth tidak memiliki genre/tag; informasi itu harus ditandai hilang, bukan direkonstruksi dari judul. Kegagalan fallback yang berbeda tetap dilaporkan, misalnya `reconnect_required` atau `rate_limited`. Tidak ada bypass Cloudflare, cookie browser, proxy tersembunyi, atau cache hasil search sendiri.

## Disconnect dan credential store

- Gunakan lock yang sama dengan login/refresh. Login yang masih pending menghasilkan error `credentials_busy`; jangan menghapus token saat callback bisa menulisnya kembali.
- Baca kredensial yang tersimpan tanpa refresh. Revoke access token serta refresh token bila ada lewat form POST `/api/auth/oauth2/revoke`, masing-masing dengan `client_id`, `token`, dan `token_type_hint` yang benar.
- Coba revoke kedua kredensial walaupun salah satunya gagal. Gunakan timeout, larang redirect, dan jangan retry otomatis permintaan revoke yang hasilnya ambigu.
- Sesudah upaya revoke, hapus lokal lewat `CredDeleteW` di Windows atau `secret-tool clear` di Linux. Tidak ada fallback file plaintext. Jangan menambah operasi clear bila client ID belum tervalidasi.
- Hasil membedakan `local_deleted`, `revocation: complete | partial | failed | not_needed`, dan warning aman. Sukses lokal dengan revoke gagal bukan klaim bahwa akses server sudah dicabut; arahkan pengguna ke [Connected apps](https://comick.dev/user/connected-apps).
- Jika penghapusan lokal gagal, hasil adalah error dan tidak mengaku disconnected. Tidak ada token disertakan di output/log. Reset status koneksi dalam proses hanya sesudah penghapusan lokal berhasil.
- Tanpa kredensial: disconnected secara idempotent. Jangan refresh atau membuka login.
- Annotation disconnect: `readOnlyHint: false`, `destructiveHint: true`, `idempotentHint: true`, `openWorldHint: true`. Annotation bukan pengganti persetujuan pengguna dari host MCP.

Token Windows tetap memakai Credential Manager yang sudah diimplementasikan. Batas blob 2.560 byte diperiksa sebelum write; token yang terlalu besar ditolak jelas, bukan dipotong. Linux tetap memakai Secret Service. Belum perlu chunking kredensial atau dependency native baru.

## Aturan error dan keamanan

- `400`: perbaiki input; jangan retry sama persis.
- `401` akun: refresh paling banyak sekali, lalu retry read sekali sesuai implementasi sekarang. Refresh ambigu tetap memerlukan reconnect, bukan reuse token lama.
- `403` akun: laporkan scope/eligibility; jangan diperlakukan sebagai challenge katalog.
- `429`: sertakan `Retry-After` jika ada; tidak ada polling atau retry storm. `503` juga dapat menyertakan `Retry-After`.
- Limit origin katalog yang didokumentasikan: 200 request/menit/IP untuk client non-exempt; library: 60/menit/app-user, 1.000/app, 120/IP. Infrastruktur bisa memberi batas tambahan. Panggilan on-demand tidak perlu scheduler limiter baru.
- ID, enum, panjang teks, halaman dan jumlah item divalidasi; tidak menerima URL endpoint bebas dari model. URL hasil hanya metadata, tidak otomatis di-fetch.
- Sinopsis, tag, ulasan, dan teks upstream adalah data tidak tepercaya, bukan instruksi model. Jangan meneruskan HTML atau ulasan mentah yang tidak diperlukan.
- `stdout` hanya pesan MCP. Log aman masuk `stderr`; jangan log token, verifier, authorization code, atau callback lengkap.
- Search/filter/detail tetap dapat digunakan tanpa akun. Library privat tidak disimpan dalam cache publik atau dimasukkan ke error.

## Urutan implementasi dan pemeriksaan

1. Normalisasi search, genre terbaca, judul tampilan, `structuredContent`, dan output schema; tambah test untuk rating string/kosong, ID genre tak dikenal, genre lookup gagal, identitas invalid, dan pemangkasan teks Unicode.
2. Normalisasi detail dan fallback terbatas; test `403`/HTML, kecocokan HID/slug, media type, belum login, metadata parsial, serta tidak fallback pada `404`/`429`/`5xx`.
3. Disconnect dengan revoke kedua token dan delete lokal; test tanpa token, access-only, revoke gagal, delete gagal, timeout, dan lock bentrok. Test native memakai credential dummy dengan target unik serta cleanup, bukan token pengguna.
4. Jalankan build, test terkait, lalu seluruh suite dan handshake MCP. Periksa output schema, annotation, tidak ada token bocor, serta tidak ada log non-MCP di stdout.

Perbaikan kecil terkait yang ikut tahap implementasi: deskripsi `comick_connect` di `src/index.ts` masih menyebut hanya Linux; jelaskan Credential Manager dan browser manual Windows. `mcp.example.json` masih berisi path Linux pribadi; ubah menjadi contoh path Windows saat contoh konfigurasi diperbarui.

## Yang sengaja tidak dibuat

Tidak ada `comick_recommend` sebagai pembungkus search, mesin ranking sendiri, database lokal, embedding, cache metadata permanen, fetch detail per hasil search, chapter images/download, OIDC, HTTP server MCP, atau write tool. Tambahkan hanya jika use case nyata tidak dapat dipenuhi oleh tool di atas.
