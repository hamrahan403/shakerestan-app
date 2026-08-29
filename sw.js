// Service Worker شکرستان
// هدف: باز شدن سریع‌تر اپ (خصوصاً روی نت موبایل) + یه صفحه‌ی قابل‌استفاده حتی بدون اینترنت
// نکته‌ی مهم: هیچ داده‌ی زنده‌ای (چت، جزوه، تسک و ...) کش نمی‌شود؛ همه‌ی این‌ها همیشه مستقیم از سرور خوانده می‌شوند.

const CACHE_NAME = 'shakerestan-shell-v1';
const SHELL_FILES = [
  '/',
  '/manifest.json',
  '/icons/icon-72.png',
  '/icons/icon-96.png',
  '/icons/icon-128.png',
  '/icons/icon-144.png',
  '/icons/icon-152.png',
  '/icons/icon-192.png',
  '/icons/icon-384.png',
  '/icons/icon-512.png'
];

// نصب: ساختار اصلی اپ رو یه‌بار توی حافظه‌ی گوشی ذخیره کن
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES))
  );
  self.skipWaiting();
});

// فعال‌سازی: نسخه‌های قدیمی کش رو پاک کن
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // درخواست‌های API/داده‌ی زنده (چت، جزوه، آپلود و ...) هرگز کش نمی‌شوند — همیشه مستقیم به سرور می‌روند
  const isLiveData = url.pathname.startsWith('/api/') || url.pathname === '/telegram-upload' || url.pathname === '/telegram-file';
  if (isLiveData) return; // اجازه بده مرورگر عادی درخواست بده (بدون دخالت Service Worker)

  // برای خودِ صفحه (index.html): اول شبکه رو امتحان کن (تا همیشه آخرین نسخه بیاد)،
  // اگه شبکه نبود یا کند/قطع بود، نسخه‌ی کش‌شده رو فوری نشون بده
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .then((res) => {
          const resClone = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put('/', resClone));
          return res;
        })
        .catch(() => caches.match('/'))
    );
    return;
  }

  // برای فایل‌های ثابت (آیکون، منیفست، فونت): اول کش (سریع)، اگه نبود برو سراغ شبکه
  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      return fetch(event.request).then((res) => {
        if (res.ok && (url.origin === location.origin || url.hostname.includes('jsdelivr'))) {
          const resClone = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, resClone));
        }
        return res;
      }).catch(() => cached);
    })
  );
});
