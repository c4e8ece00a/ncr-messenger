const CACHE_NAME =
  'ncr-messenger-v3';

const APP_SHELL = [
  '/',
  '/index.html',
  '/style.css',
  '/app.js',
  '/ncr-lwe.js',
  '/manifest.json'
];

/* =========================================================
   INSTALL
========================================================= */

self.addEventListener(
  'install',
  event => {

    event.waitUntil(
      caches
        .open(CACHE_NAME)
        .then(cache =>
          cache.addAll(APP_SHELL)
        )
        .then(() =>
          self.skipWaiting()
        )
    );
  }
);

/* =========================================================
   ACTIVATE
========================================================= */

self.addEventListener(
  'activate',
  event => {

    event.waitUntil(
      caches
        .keys()
        .then(keys =>
          Promise.all(
            keys
              .filter(
                key =>
                  key !== CACHE_NAME
              )
              .map(key =>
                caches.delete(key)
              )
          )
        )
        .then(() =>
          self.clients.claim()
        )
    );
  }
);

/* =========================================================
   FETCH
========================================================= */

self.addEventListener(
  'fetch',
  event => {

    const request =
      event.request;

    /*
     * API НИКОГДА не берём из кэша.
     */
    if (
      new URL(request.url)
        .pathname
        .startsWith('/api/')
    ) {
      event.respondWith(
        fetch(request)
      );

      return;
    }

    /*
     * HTML / JS / CSS:
     *
     * сначала пытаемся получить
     * свежую версию из сети.
     */
    if (
      request.method === 'GET'
    ) {
      event.respondWith(
        fetch(request)
          .then(response => {

            const copy =
              response.clone();

            caches
              .open(CACHE_NAME)
              .then(cache =>
                cache.put(
                  request,
                  copy
                )
              );

            return response;
          })
          .catch(() =>
            caches.match(request)
          )
      );
    }
  }
);
