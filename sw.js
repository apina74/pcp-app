// Service worker: cachea el armazón estático para que la app abra offline.
// Los datos (vistas v_cm_* y Q&A) NUNCA se cachean: siempre se piden frescos a la red.
// v18: navegación RED-PRIMERO (las versiones nuevas entran a la primera apertura;
// la caché solo responde sin conexión) + instalación saltándose la caché HTTP.
const CACHE = 'pcp-v27';
const ASSETS = [
  './index.html',
  './styles.css',
  './app.js',
  './manifest.webmanifest',
  './icon.svg',
  './icon-96.png',
  './icon-192.png',
  './icon-512.png',
  'https://cdn.jsdelivr.net/npm/chart.js@4.5.0/dist/chart.umd.js',
  'https://cdn.jsdelivr.net/npm/jspdf@2.5.2/dist/jspdf.umd.min.js',
  'https://cdn.jsdelivr.net/npm/jspdf-autotable@3.8.4/dist/jspdf.plugin.autotable.min.js',
  'https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js'
];

self.addEventListener('install', (e) => {
  // cache: 'reload' evita heredar copias viejas de la caché HTTP del navegador
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => c.addAll(ASSETS.map((u) => new Request(u, { cache: 'reload' }))))
      .then(() => self.skipWaiting())
  );
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
  // Navegación (abrir la app): red primero — así cada publicación entra a la primera.
  if (e.request.mode === 'navigate') {
    e.respondWith(
      fetch(e.request)
        .then((r) => {
          const copia = r.clone();
          caches.open(CACHE).then((c) => c.put('./index.html', copia));
          return r;
        })
        .catch(() => caches.match('./index.html'))
    );
    return;
  }
  // Resto de assets: caché primero, red de respaldo.
  e.respondWith(caches.match(e.request).then((hit) => hit || fetch(e.request)));
});

// ===== FASE J: notificaciones push =====
self.addEventListener('push', (e) => {
  let datos = { titulo: 'Kira', cuerpo: 'Tienes novedades en el PCP.' };
  try { datos = e.data.json(); } catch {}
  e.waitUntil(
    self.registration.showNotification(datos.titulo || 'Kira', {
      body: datos.cuerpo || '',
      // 96px (48 DIP × 2): con 192px, Windows 11 recortaba el icono del toast al cuadrante
      // superior izquierdo; con 96px se ve completo (CONFIRMADO por Antonio, 22-07).
      icon: './icon-96.png',
      badge: './icon-96.png',
      data: { url: './' },
    })
  );
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientes) => {
      for (const c of clientes) { if ('focus' in c) return c.focus(); }
      if (self.clients.openWindow) return self.clients.openWindow('./');
    })
  );
});
