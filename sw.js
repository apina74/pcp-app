// Service worker mínimo: cachea el armazón estático para que la app abra offline.
// Los datos (vistas v_cm_* y Q&A) NUNCA se cachean: siempre se piden frescos a la red.
const CACHE = 'pcp-v9';
const ASSETS = [
  './index.html',
  './styles.css',
  './app.js',
  './manifest.webmanifest',
  './icon.svg',
  './icon-192.png',
  './icon-512.png',
  'https://cdn.jsdelivr.net/npm/chart.js@4.5.0/dist/chart.umd.js'
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  // Datos de Supabase (REST y Edge Functions): siempre red, nunca caché.
  if (url.hostname.endsWith('.supabase.co')) return;
  // Resto: caché primero, red de respaldo.
  e.respondWith(caches.match(e.request).then((hit) => hit || fetch(e.request)));
});
