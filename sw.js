// Scam Bunker service worker: makes the hosted (static) app installable and usable offline.
// Registered by public/pwa.js only in static mode on a secure origin, never by the local server or `npm run dev`.
// scripts/build-pages.js replaces VERSION with a content hash of the build and ASSETS with the app shell file list,
// so every deploy that changes a file gets a fresh cache and an "Update available" prompt.
// Strategy: HTML is network-first (cache fallback); other same-origin assets are stale-while-revalidate.
// Never cached: /api/*, the dev live-reload stream, non-GET requests and anything cross-origin (third-party APIs, fonts).
const VERSION = "727ae25c840a";
const ASSETS = ["./","./app.css","./app.js","./corroborate.js","./custody.js","./dossier.js","./events-core.js","./events.css","./events.js","./factcheck.js","./forensics.js","./grading.js","./icons/icon-192.png","./icons/icon-512.png","./icons/icon-maskable-192.png","./icons/icon-maskable-512.png","./icons/icon.svg","./index.html","./manifest.webmanifest","./osint.css","./osint.js","./provenance.js","./pwa.css","./pwa.js","./scam.js","./shared/claims.js","./shared/corroborate-core.js","./shared/prompt.js","./similar.js","./simple.js","./video.js"];
const PREFIX = 'scam-bunker-';
const CACHE = PREFIX + VERSION;

const scopeUrl = () => new URL(self.registration ? self.registration.scope : './', self.location.href);

function cacheable(request) {
  if (request.method !== 'GET') return false;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return false;
  if (!url.href.startsWith(scopeUrl().href)) return false;
  return !/\/(api|__dev)(\/|$)/.test(url.pathname);
}

const isHtml = (request) => request.mode === 'navigate' || (request.headers.get('accept') || '').includes('text/html');
const storable = (res) => res && res.ok && res.type === 'basic';

async function networkFirst(event) {
  const cache = await caches.open(CACHE);
  try {
    const res = await fetch(event.request);
    if (storable(res)) event.waitUntil(cache.put(event.request, res.clone()));
    return res;
  } catch (err) {
    return (await cache.match(event.request, { ignoreSearch: true })) || (await cache.match('./index.html')) || (await cache.match('./')) || Response.error();
  }
}

async function staleWhileRevalidate(event) {
  const cache = await caches.open(CACHE);
  const cached = await cache.match(event.request);
  const refresh = fetch(event.request).then((res) => { if (storable(res)) return cache.put(event.request, res.clone()).then(() => res); return res; });
  if (cached) { event.waitUntil(refresh.catch(() => {})); return cached; }
  return refresh;
}

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(ASSETS.map((a) => new Request(a, { cache: 'reload' })))));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((k) => k.startsWith(PREFIX) && k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

// pwa.js posts this when the user clicks "Reload" on the update prompt.
self.addEventListener('message', (event) => { if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting(); });

self.addEventListener('fetch', (event) => {
  if (!cacheable(event.request)) return;
  event.respondWith(isHtml(event.request) ? networkFirst(event) : staleWhileRevalidate(event));
});
