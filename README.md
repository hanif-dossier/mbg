# MBG

Aplikasi laporan usaha pribadi. Halaman ini hanya berisi kode tampilan; semua data (angka, nama usaha, pelanggan,
rekening) tersimpan di database dan hanya terbaca setelah masuk dengan sandi pemilik.

| Berkas | Isi |
|---|---|
| `index.html` | Seluruh aplikasi (satu berkas, tanpa build). |
| `supabase/skema.sql` | Tabel dan fungsi database. Semua tabel dikunci; akses hanya lewat fungsi dengan sesi sandi. |
