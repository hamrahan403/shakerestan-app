// Shakerestan - Service Worker
// هدف: فقط قابل نصب کردن اپ (PWA) رو ممکن می‌کنه و یه آفلاین ساده هم اضافه می‌کنه.
// این فایل نباید API/داده‌های زنده (چت، جزوه‌ها، ورود) رو کش کنه.

const CACHE_NAME = 'shakerestan-shell-v1';
const APP_SHELL = [
  '/',
  '/index.html'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const { request } = event;

  // فقط درخواست‌های GET رو دست می‌زنیم؛ API/POST ها دست‌نخورده رد می‌شن
  if (request.method !== 'GET') return;

  const url = new URL(request.url);

  // درخواست‌های API یا هر چیزی که مسیرش شامل /api باشه رو اصلاً کش نکن
  if (url.pathname.startsWith('/api')) return;

  // فقط برای درخواست ناوبری صفحه (رفرش/بازکردن اپ) از حالت آفلاین fallback استفاده کن
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request).catch(() => caches.match('/index.html'))
    );
    return;
  }

  // برای بقیه (CSS/JS/عکس‌های استاتیک واقعی): شبکه اول، در صورت قطعی از کش
  event.respondWith(
    fetch(request).catch(() => caches.match(request))
  );
});
