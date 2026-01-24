// Progressive Web App service worker
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open('eencrypt-cache').then(cache => {
      return cache.addAll([
        '/',
        '/index.html',
        '/main.py',
        '/manifest.json'
      ]);
    })
  );
});