// Service worker aplikasi MBG: halaman diambil dari jaringan dulu (supaya versi baru langsung terpakai),
// salinan terakhir dipakai kalau sedang tidak ada sinyal. Data laporan tidak disimpan di sini (selalu dari server).
const CACHE = 'mbg-v11';
const ASET = ['./', 'index.html', 'manifest.webmanifest', 'ikon-any-192.png?v=1', 'ikon-180.png?v=1'];
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASET)).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(k => Promise.all(k.filter(x => x !== CACHE).map(x => caches.delete(x)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin) return;
  e.respondWith(fetch(e.request).then(r => { const s = r.clone(); caches.open(CACHE).then(c => c.put(e.request, s)); return r; }).catch(() => caches.match(e.request).then(r => r || caches.match('index.html'))));
});
