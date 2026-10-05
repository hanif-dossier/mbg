-- MBG: skema database aplikasi laporan usaha pribadi, tabel berawalan mbg_.
-- Polanya sama dengan aplikasi Minyak Andre (absensi/supabase/skema.sql):
--   * tidak memakai auth.users, jadi tidak terkait akun Markasku, Hanif Dossier, maupun Minyak Andre;
--   * semua tabel dikunci RLS tanpa kebijakan; satu-satunya pintu adalah fungsi SECURITY DEFINER di bawah;
--   * pemilik masuk dengan sandi (bcrypt), dapat token sesi 30 hari (yang disimpan hanya sha256-nya);
--   * laptop pemilik (n8n) menulis data lewat kunci sinkron sempit (hanya sha256-nya yang disimpan di sini).
-- Kunci aslinya ada di D:\Ai Agent\rahasia\mbg.txt (SANDI_PEMILIK, SINKRON_KUNCI), tidak pernah masuk repo.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.mbg_pemilik (
  id int primary key default 1 check (id = 1),   -- satu baris saja
  sandi_hash text not null,                       -- bcrypt
  sinkron_hash text,                              -- sha256 kunci sinkron laptop
  gagal int not null default 0,                   -- salah sandi berturut-turut
  kunci_sampai timestamptz                        -- terkunci sementara sampai waktu ini
);
create table if not exists public.mbg_sesi (
  token_hash text primary key,                    -- sha256(token); token asli hanya ada di HP pemakai
  dibuat timestamptz not null default now(),
  kedaluwarsa timestamptz not null
);
create table if not exists public.mbg_nilai (
  kunci text primary key,                         -- 'data' (hasil baca Excel), 'pembaruan' (catatan putaran otomatis)
  nilai jsonb not null,
  diubah timestamptz not null default now()
);
alter table public.mbg_pemilik enable row level security;
alter table public.mbg_sesi    enable row level security;
alter table public.mbg_nilai   enable row level security;

create or replace function public.mbg__h(t text) returns text language sql immutable
set search_path = public, extensions as $f$ select encode(extensions.digest(t, 'sha256'), 'hex') $f$;

-- MASUK. Salah 5 kali berturut-turut => terkunci 15 menit. Mengembalikan {ok:false} (bukan raise) supaya hitungan
-- gagal tidak ikut dibatalkan.
create or replace function public.mbg_masuk(p_sandi text) returns jsonb language plpgsql security definer
set search_path = public, extensions as $f$
declare v_hash text; v_kunci timestamptz; v_token text;
begin
  select sandi_hash, kunci_sampai into v_hash, v_kunci from mbg_pemilik where id = 1;
  if v_kunci is not null and v_kunci > now() then
    return jsonb_build_object('ok', false, 'pesan', 'Terlalu banyak percobaan. Coba lagi pukul ' || to_char(v_kunci at time zone 'Asia/Jakarta', 'HH24:MI') || ' WIB.');
  end if;
  if v_hash is null or p_sandi is null or v_hash <> extensions.crypt(p_sandi, v_hash) then
    update mbg_pemilik set kunci_sampai = case when gagal + 1 >= 5 then now() + interval '15 minutes' else kunci_sampai end,
                           gagal = case when gagal + 1 >= 5 then 0 else gagal + 1 end where id = 1;
    return jsonb_build_object('ok', false, 'pesan', 'Sandi salah.');
  end if;
  update mbg_pemilik set gagal = 0, kunci_sampai = null where id = 1;
  v_token := encode(extensions.gen_random_bytes(24), 'hex');
  delete from mbg_sesi where kedaluwarsa < now();
  insert into mbg_sesi(token_hash, kedaluwarsa) values (mbg__h(v_token), now() + interval '30 days');
  return jsonb_build_object('ok', true, 'token', v_token);
end $f$;

create or replace function public.mbg_keluar(p_token text) returns jsonb language sql security definer
set search_path = public, extensions as $f$
  with d as (delete from public.mbg_sesi where token_hash = public.mbg__h(coalesce(p_token,'')) returning 1) select jsonb_build_object('ok', true) $f$;

create or replace function public.mbg_ganti_sandi(p_token text, p_lama text, p_baru text) returns jsonb language plpgsql security definer
set search_path = public, extensions as $f$
declare v_hash text;
begin
  if not exists (select 1 from mbg_sesi where token_hash = mbg__h(coalesce(p_token,'')) and kedaluwarsa > now()) then
    return jsonb_build_object('ok', false, 'pesan', 'Sesi habis. Masuk lagi.'); end if;
  if coalesce(length(p_baru), 0) < 6 then return jsonb_build_object('ok', false, 'pesan', 'Sandi baru minimal 6 karakter.'); end if;
  select sandi_hash into v_hash from mbg_pemilik where id = 1;
  if v_hash <> extensions.crypt(coalesce(p_lama,''), v_hash) then return jsonb_build_object('ok', false, 'pesan', 'Sandi lama salah.'); end if;
  update mbg_pemilik set sandi_hash = extensions.crypt(p_baru, extensions.gen_salt('bf', 10)) where id = 1;
  return jsonb_build_object('ok', true);
end $f$;

-- BACA: pemilik yang sesinya sah.
create or replace function public.mbg_ambil_nilai(p_token text, p_kunci text) returns jsonb language plpgsql stable security definer
set search_path = public, extensions as $f$
begin
  if not exists (select 1 from mbg_sesi where token_hash = mbg__h(coalesce(p_token,'')) and kedaluwarsa > now()) then
    return jsonb_build_object('ok', false, 'pesan', 'Sesi habis. Masuk lagi.'); end if;
  return jsonb_build_object('ok', true, 'nilai', (select nilai from mbg_nilai where kunci = p_kunci),
    'diubah', (select diubah from mbg_nilai where kunci = p_kunci));
end $f$;

-- TULIS dari laptop (n8n): hanya kunci yang diizinkan, dengan kunci sinkron.
create or replace function public.mbg_tulis_nilai(p_rahasia text, p_kunci text, p_nilai jsonb) returns jsonb language plpgsql security definer
set search_path = public, extensions as $f$
begin
  if p_kunci not in ('data', 'pembaruan', 'catatan') then return jsonb_build_object('ok', false, 'pesan', 'kunci tidak diizinkan'); end if;
  if coalesce(length(p_rahasia), 0) < 32 or not exists (select 1 from mbg_pemilik where id = 1 and sinkron_hash = mbg__h(p_rahasia)) then
    return jsonb_build_object('ok', false, 'pesan', 'ditolak'); end if;
  insert into mbg_nilai(kunci, nilai) values (p_kunci, p_nilai) on conflict (kunci) do update set nilai = excluded.nilai, diubah = now();
  return jsonb_build_object('ok', true);
end $f$;

revoke all on function public.mbg__h(text) from public, anon, authenticated;
grant execute on function public.mbg_masuk(text), public.mbg_keluar(text), public.mbg_ganti_sandi(text,text,text),
  public.mbg_ambil_nilai(text,text), public.mbg_tulis_nilai(text,text,jsonb) to anon, authenticated;
notify pgrst, 'reload schema';

-- =====================================================================================================
-- INVOICE ke dapur dan TARIF FEE (26 Sep 2026). Dibuat dan disimpan dari aplikasi oleh pemilik yang sesinya sah.
-- Invoice aplikasi TIDAK menulis ke Excel (aturan: jangan menimpa pekerjaan Hanif); pemilik bisa mengunduh Excel-nya.
-- =====================================================================================================
create table if not exists public.mbg_invoice (
  id text primary key,
  data jsonb not null,               -- { id, nomor, tanggal, outlet, toko, alamat, penerbit, rekening, baris:[{barang,qty,satuan,harga,fee,modal}], diskon }
  dibuat timestamptz not null default now(),
  diubah timestamptz not null default now()
);
alter table public.mbg_invoice enable row level security;

create or replace function public.mbg__sah(p_token text) returns boolean language sql stable security definer
set search_path = public, extensions as $f$
  select exists (select 1 from public.mbg_sesi where token_hash = public.mbg__h(coalesce(p_token,'')) and kedaluwarsa > now()) $f$;

create or replace function public.mbg_invoice_daftar(p_token text) returns jsonb language plpgsql stable security definer
set search_path = public, extensions as $f$
begin
  if not mbg__sah(p_token) then return jsonb_build_object('ok', false, 'pesan', 'Sesi habis. Masuk lagi.'); end if;
  return jsonb_build_object('ok', true, 'invoice', coalesce((select jsonb_agg(data order by data->>'tanggal' desc, dibuat desc) from mbg_invoice), '[]'::jsonb));
end $f$;

create or replace function public.mbg_invoice_simpan(p_token text, p_data jsonb) returns jsonb language plpgsql security definer
set search_path = public, extensions as $f$
declare v_id text := coalesce(nullif(p_data->>'id', ''), encode(extensions.gen_random_bytes(8), 'hex'));
begin
  if not mbg__sah(p_token) then return jsonb_build_object('ok', false, 'pesan', 'Sesi habis. Masuk lagi.'); end if;
  if jsonb_typeof(p_data->'baris') is distinct from 'array' then return jsonb_build_object('ok', false, 'pesan', 'Barang belum diisi.'); end if;
  insert into mbg_invoice(id, data) values (v_id, jsonb_set(p_data, '{id}', to_jsonb(v_id)))
    on conflict (id) do update set data = excluded.data, diubah = now();
  return jsonb_build_object('ok', true, 'id', v_id);
end $f$;

create or replace function public.mbg_invoice_hapus(p_token text, p_id text) returns jsonb language plpgsql security definer
set search_path = public, extensions as $f$
begin
  if not mbg__sah(p_token) then return jsonb_build_object('ok', false, 'pesan', 'Sesi habis. Masuk lagi.'); end if;
  delete from mbg_invoice where id = p_id;
  return jsonb_build_object('ok', true);
end $f$;

-- Nilai yang diisi pemilik dari aplikasi (saat ini hanya tarif fee per dapur per barang).
create or replace function public.mbg_simpan_nilai(p_token text, p_kunci text, p_nilai jsonb) returns jsonb language plpgsql security definer
set search_path = public, extensions as $f$
begin
  if not mbg__sah(p_token) then return jsonb_build_object('ok', false, 'pesan', 'Sesi habis. Masuk lagi.'); end if;
  if p_kunci not in ('tarif-fee', 'karyawan', 'pengeluaran', 'piutang', 'dapur', 'stok', 'rekening') then return jsonb_build_object('ok', false, 'pesan', 'kunci tidak diizinkan'); end if;
  insert into mbg_nilai(kunci, nilai) values (p_kunci, p_nilai) on conflict (kunci) do update set nilai = excluded.nilai, diubah = now();
  return jsonb_build_object('ok', true);
end $f$;

revoke all on function public.mbg__sah(text) from public, anon, authenticated;
grant execute on function public.mbg_invoice_daftar(text), public.mbg_invoice_simpan(text,jsonb), public.mbg_invoice_hapus(text,text),
  public.mbg_simpan_nilai(text,text,jsonb) to anon, authenticated;
notify pgrst, 'reload schema';

-- =====================================================================================================
-- SINKRON INVOICE ke laptop: laptop (n8n, dengan kunci sinkron) mengambil semua invoice untuk disalin sebagai
-- berkas Excel di D:\MBG\INVOICE APLIKASI. Hanya membaca.
create or replace function public.mbg_invoice_sinkron(p_rahasia text) returns jsonb language plpgsql stable security definer
set search_path = public, extensions as $f$
begin
  if coalesce(length(p_rahasia), 0) < 32 or not exists (select 1 from mbg_pemilik where id = 1 and sinkron_hash = mbg__h(p_rahasia)) then
    return jsonb_build_object('ok', false, 'pesan', 'ditolak'); end if;
  return jsonb_build_object('ok', true, 'invoice', coalesce((select jsonb_agg(data order by data->>'tanggal', dibuat) from mbg_invoice), '[]'::jsonb),
    'dapur', (select nilai from mbg_nilai where kunci = 'dapur'), 'bayar', (select nilai->'bayar' from mbg_nilai where kunci = 'piutang'));
end $f$;
grant execute on function public.mbg_invoice_sinkron(text) to anon, authenticated;
notify pgrst, 'reload schema';

-- =====================================================================================================
-- GAJI NTA dari aplikasi OFU (1 Okt 2026): absensi & gaji karyawan NTA dicatat di OFU (minyak_karyawan, data.nta).
-- Aplikasi NTA hanya membaca: nama, aktif, lembar NTA (minggu, hari), dan hutang/pinjaman yang berkaitan dengan NTA.
-- =====================================================================================================
create or replace function public.mbg_gaji_nta(p_token text) returns jsonb language plpgsql stable security definer
set search_path = public, extensions as $f$
begin
  if not mbg__sah(p_token) then return jsonb_build_object('ok', false, 'pesan', 'Sesi habis. Masuk lagi.'); end if;
  return jsonb_build_object('ok', true, 'karyawan', coalesce((select jsonb_agg(jsonb_build_object('kode', kode, 'nama', data->>'nama', 'aktif', coalesce((data->>'aktif')::boolean, true), 'nta', coalesce(data->'nta', '[]'::jsonb),
      'hutang', coalesce((select jsonb_agg(h) from jsonb_array_elements(coalesce(data->'hutang', '[]'::jsonb)) h where h->>'ket' ilike '%NTA%' or h->>'usaha' = 'nta'), '[]'::jsonb)) order by kode)
    from minyak_karyawan where jsonb_array_length(coalesce(data->'nta', '[]'::jsonb)) > 0), '[]'::jsonb),
    'diubah', (select max(diubah) from minyak_karyawan));
end $f$;
grant execute on function public.mbg_gaji_nta(text) to anon, authenticated;
notify pgrst, 'reload schema';
