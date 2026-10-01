# NTA (Needs that Arise)

Aplikasi laporan usaha pribadi. Halaman ini hanya berisi kode tampilan; semua data (angka, nama usaha, pelanggan,
rekening) tersimpan di database dan hanya terbaca setelah masuk dengan sandi pemilik.

| Berkas | Isi |
|---|---|
| `index.html` | Seluruh aplikasi (satu berkas, tanpa build). |
| `supabase/skema.sql` | Tabel dan fungsi database. Semua tabel dikunci; akses hanya lewat fungsi dengan sesi sandi. |

## Absensi & gaji (1 Okt 2026)

Absensi dan gaji karyawan NTA tidak lagi dicatat di aplikasi ini. Semuanya diisi di aplikasi OFU (Oil for Us,
minyak.markasku.my.id) pada lembar gaji **NTA** tiap karyawan, karena sebagian karyawan bekerja di dua usaha dan ingin
melihat gajinya di satu tempat. Aplikasi ini membaca lembar itu lewat `mbg_gaji_nta` (hanya baca; database yang sama)
dan menyusunnya jadi gaji per tanggal (`bangunKry`) supaya pekan Minggu sampai Sabtu, beranda, dan laba rugi tetap
jalan. Halaman Operasional > Absensi & gaji hanya menampilkan angkanya dan tautan ke OFU.
