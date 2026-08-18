const CACHE_NAME = 'ncr-messenger-v3.2.0';

const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/style.css',
  '/app.js',
  '/ncr-lwe.js',
  '/manifest.json'
];

/*
 * INSTALL
 */
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(STATIC_ASSETS))
      .then(() => self.skipWaiting())
  );
});

/*
 * ACTIVATE
 */
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key !== CACHE_NAME)
            .map((key) => caches.delete(key))
        )
      )
      .then(() => self.clients.claim())
  );
});

/*
 * FETCH
 *
 * API НИКОГДА не кэшируем.
 */
self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);

  if (
    url.origin === self.location.origin &&
    url.pathname.startsWith('/api/')
  ) {
    return;
  }

  if (request.method !== 'GET') {
    return;
  }

  event.respondWith(
    fetch(request)
      .then((response) => {
        if (response.ok) {
          const copy = response.clone();

          caches
            .open(CACHE_NAME)
            .then((cache) => cache.put(request, copy))
            .catch(() => {});
        }

        return response;
      })
      .catch(() => caches.match(request))
  );
});

/*
 * PUSH
 */
self.addEventListener('push', (event) => {
  let data = {};

  try {
    data = event.data
      ? event.data.json()
      : {};
  } catch {
    data = {};
  }

  if (data.type !== 'new-message') {
    return;
  }

  const sender =
    typeof data.sender === 'string' &&
    data.sender.length <= 32
      ? data.sender
      : 'Пользователь';

  const title = 'NCR Messenger';

  const options = {
    body: `Новое сообщение от ${sender}`,
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    tag: `ncr-message-${data.messageId || Date.now()}`,
    renotify: true,
    data: {
      type: 'new-message',
      messageId: data.messageId || null
    }
  };

  event.waitUntil(
    (async () => {
      /*
       * Увеличиваем badge.
       */
      try {
        const current =
          typeof navigator !== 'undefined' &&
          navigator.setAppBadge
            ? null
            : null;

        void current;
      } catch {}
      
      await self.registration.showNotification(
        title,
        options
      );

      /*
       * Сообщаем открытому приложению,
       * что пришло новое сообщение.
       */
      const clientsList =
        await self.clients.matchAll({
          type: 'window',
          includeUncontrolled: true
        });

      for (const client of clientsList) {
        client.postMessage({
          type: 'push-message',
          messageId: data.messageId || null
        });
      }
    })()
  );
});

/*
 * CLICK NOTIFICATION
 */
self.addEventListener(
  'notificationclick',
  (event) => {
    event.notification.close();

    event.waitUntil(
      (async () => {
        const windowClients =
          await self.clients.matchAll({
            type: 'window',
            includeUncontrolled: true
          });

        for (const client of windowClients) {
          if ('focus' in client) {
            await client.focus();

            client.postMessage({
              type: 'notification-click',
              messageId:
                event.notification.data?.messageId ||
                null
            });

            return;
          }
        }

        if (self.clients.openWindow) {
          await self.clients.openWindow('/');
        }
      })()
    );
  }
);