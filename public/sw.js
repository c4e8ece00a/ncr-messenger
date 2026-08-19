const CACHE_NAME =
  'ncr-messenger-v3-3';

const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/style.css',
  '/app.js',
  '/ncr-lwe.js',
  '/manifest.json'
];

self.addEventListener(
  'install',
  event => {
    event.waitUntil(
      caches
        .open(
          CACHE_NAME
        )
        .then(cache =>
          cache.addAll(
            STATIC_ASSETS
          )
        )
        .then(() =>
          self.skipWaiting()
        )
    );
  }
);


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
                  key !==
                  CACHE_NAME
              )
              .map(key =>
                caches.delete(
                  key
                )
              )
          )
        )
        .then(() =>
          self.clients.claim()
        )
    );
  }
);


/* =========================
   PUSH
========================= */

self.addEventListener(
  'push',
  event => {
    let data = {};

    try {
      data =
        event.data
          ? event.data.json()
          : {};
    } catch {
      data = {};
    }

    const sender =
      typeof data.sender ===
        'string'
        ? data.sender
        : 'Новое сообщение';

    const title =
      'NCR Messenger';

    const options = {
      body:
        `${sender}: новое сообщение`,

      icon:
        '/icon-192.png',

      badge:
        '/icon-192.png',

      tag:
        `message-${data.messageId || Date.now()}`,

      renotify:
        true,

      requireInteraction:
        false,

      data: {
        url:
          data.url || '/',

        messageId:
          data.messageId ||
          null
      }
    };

    event.waitUntil(
      self.registration
        .showNotification(
          title,
          options
        )
        .then(async () => {
          if (
            'setAppBadge' in
            self.registration
          ) {
            try {
              await self.registration
                .setAppBadge(1);
            } catch {}
          }
        })
    );
  }
);


/* =========================
   NOTIFICATION CLICK
========================= */

self.addEventListener(
  'notificationclick',
  event => {
    event.notification.close();

    event.waitUntil(
      clients.matchAll({
        type:
          'window',

        includeUncontrolled:
          true
      })
      .then(clientList => {
        for (
          const client of
          clientList
        ) {
          if (
            'focus' in client
          ) {
            return client.focus();
          }
        }

        if (
          clients.openWindow
        ) {
          return clients.openWindow(
            event.notification
              ?.data
              ?.url || '/'
          );
        }

        return undefined;
      })
    );
  }
);


/* =========================
   FETCH
========================= */

self.addEventListener(
  'fetch',
  event => {
    const request =
      event.request;

    const url =
      new URL(
        request.url
      );

    /*
     * API никогда не кэшируем.
     */
    if (
      url.origin ===
        self.location.origin &&
      url.pathname.startsWith(
        '/api/'
      )
    ) {
      return;
    }

    if (
      request.method !==
      'GET'
    ) {
      return;
    }

    /*
     * HTML и JS сначала
     * пытаемся получить
     * из сети.
     *
     * Это важно для обновления
     * приложения на iPhone.
     */
    if (
      request.destination ===
        'document' ||
      request.destination ===
        'script'
    ) {
      event.respondWith(
        fetch(request)
          .then(response => {
            const copy =
              response.clone();

            caches
              .open(
                CACHE_NAME
              )
              .then(cache =>
                cache.put(
                  request,
                  copy
                )
              )
              .catch(() => {});

            return response;
          })
          .catch(() =>
            caches.match(
              request
            )
          )
      );

      return;
    }

    event.respondWith(
      fetch(request)
        .then(response => {
          const copy =
            response.clone();

          caches
            .open(
              CACHE_NAME
            )
            .then(cache =>
              cache.put(
                request,
                copy
              )
            )
            .catch(() => {});

          return response;
        })
        .catch(() =>
          caches.match(
            request
          )
        )
    );
  }
);