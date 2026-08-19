let username = null;
let privateKey = null;
let publicKey = null;
let deviceId = null;

let pollingTimer = null;
let pollingInProgress = false;
let authInProgress = false;

const renderedMessageIds = new Set();

const $ = (id) =>
  document.getElementById(id);


function createDeviceId() {
  const bytes =
    crypto.getRandomValues(
      new Uint8Array(24)
    );

  return Array.from(bytes)
    .map((value) =>
      value.toString(16).padStart(2, '0')
    )
    .join('');
}


function getDeviceId() {
  let id =
    localStorage.getItem(
      'ncr_device_id'
    );

  if (
    !id ||
    id.length < 16
  ) {
    id = createDeviceId();

    localStorage.setItem(
      'ncr_device_id',
      id
    );
  }

  return id;
}


function keyStorageName(name) {
  return `ncrlwe_keys:${name}:${deviceId}`;
}


function loadOrGenerateKeys(name) {
  const storageKey =
    keyStorageName(name);

  const stored =
    localStorage.getItem(
      storageKey
    );

  if (stored) {
    try {
      const parsed =
        JSON.parse(stored);

      if (
        parsed?.privateKey &&
        parsed?.publicKey
      ) {
        privateKey =
          parsed.privateKey;

        publicKey =
          parsed.publicKey;

        return;
      }
    } catch {
      localStorage.removeItem(
        storageKey
      );
    }
  }

  const keys =
    NCRLWE.generateKeypair();

  privateKey =
    keys.privateKey;

  publicKey =
    keys.publicKey;

  localStorage.setItem(
    storageKey,
    JSON.stringify({
      privateKey,
      publicKey
    })
  );
}


async function deriveAesKey(K) {
  const bytes =
    NCRLWE.matrixToBytes(K);

  const hash =
    await crypto.subtle.digest(
      'SHA-256',
      bytes
    );

  return crypto.subtle.importKey(
    'raw',
    hash,
    {
      name: 'AES-GCM'
    },
    false,
    [
      'encrypt',
      'decrypt'
    ]
  );
}


async function encryptMessage(
  aesKey,
  plaintext
) {
  const nonce =
    crypto.getRandomValues(
      new Uint8Array(12)
    );

  const encoded =
    new TextEncoder().encode(
      plaintext
    );

  const ciphertext =
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce
      },
      aesKey,
      encoded
    );

  return {
    nonce: Array.from(nonce),

    ciphertext: Array.from(
      new Uint8Array(ciphertext)
    )
  };
}


async function decryptMessage(
  aesKey,
  nonce,
  ciphertext
) {
  const decoded =
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: new Uint8Array(nonce)
      },
      aesKey,
      new Uint8Array(ciphertext)
    );

  return new TextDecoder()
    .decode(decoded);
}


async function readJsonResponse(res) {
  const text =
    await res.text();

  let data = {};

  try {
    data =
      text
        ? JSON.parse(text)
        : {};
  } catch {}

  if (!res.ok) {
    throw new Error(
      data.error ||
      `HTTP ${res.status}`
    );
  }

  return data;
}


async function apiAuth(
  name,
  password,
  key,
  currentDeviceId
) {
  const res =
    await fetch('/api/auth', {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'Content-Type':
          'application/json'
      },
      body: JSON.stringify({
        username: name,
        password,
        deviceId: currentDeviceId,
        publicKey: key
      })
    });

  return readJsonResponse(res);
}


async function apiGetPublicKeys(name) {
  const url =
    `/api/publicKey?username=${encodeURIComponent(name)}&_=${Date.now()}`;

  const res =
    await fetch(url, {
      method: 'GET',
      cache: 'no-store'
    });

  const data =
    await readJsonResponse(res);

  return Array.isArray(data.devices)
    ? data.devices
    : [];
}


async function apiSend(
  recipient,
  payloads
) {
  const res =
    await fetch('/api/send', {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'Content-Type':
          'application/json'
      },
      body: JSON.stringify({
        recipient,
        payloads
      })
    });

  return readJsonResponse(res);
}


async function apiGetMessages() {
  const url =
    `/api/messages?username=${encodeURIComponent(username)}&_=${Date.now()}`;

  const res =
    await fetch(url, {
      method: 'GET',
      cache: 'no-store'
    });

  return readJsonResponse(res);
}


async function apiGetPushConfig() {
  const res =
    await fetch(
      '/api/push/config',
      {
        method: 'GET',
        cache: 'no-store'
      }
    );

  return readJsonResponse(res);
}


async function apiSubscribePush(
  subscription
) {
  const res =
    await fetch(
      '/api/push/subscribe',
      {
        method: 'POST',
        cache: 'no-store',
        headers: {
          'Content-Type':
            'application/json'
        },
        body: JSON.stringify({
          subscription
        })
      }
    );

  return readJsonResponse(res);
}


async function apiUnsubscribePush(
  endpoint
) {
  const res =
    await fetch(
      '/api/push/unsubscribe',
      {
        method: 'POST',
        cache: 'no-store',
        headers: {
          'Content-Type':
            'application/json'
        },
        body: JSON.stringify({
          endpoint
        })
      }
    );

  return readJsonResponse(res);
}


function setStatus(
  text,
  isError = false
) {
  $('status-bar').textContent =
    text || '';

  $('status-bar')
    .classList.toggle(
      'error',
      isError
    );
}


function showChat(name) {
  $('current-user')
    .textContent = name;

  $('user-avatar')
    .textContent =
    name.charAt(0).toUpperCase();

  $('login-screen')
    .classList.add('hidden');

  $('chat-screen')
    .classList.remove('hidden');

  setStatus('Подключено');
}


function showLogin() {
  $('chat-screen')
    .classList.add('hidden');

  $('login-screen')
    .classList.remove('hidden');
}


function formatTime(timestamp) {
  if (!timestamp) return '';

  return new Intl.DateTimeFormat(
    'ru-RU',
    {
      hour: '2-digit',
      minute: '2-digit'
    }
  ).format(
    new Date(timestamp)
  );
}


function addMessage(
  text,
  {
    outgoing,
    sender,
    timestamp,
    id
  }
) {
  if (
    id &&
    renderedMessageIds.has(id)
  ) {
    return;
  }

  if (id) {
    renderedMessageIds.add(id);
  }

  const empty =
    $('empty-state');

  if (empty) {
    empty.remove();
  }

  const wrap =
    document.createElement('div');

  wrap.className =
    `message-wrap ${
      outgoing
        ? 'outgoing'
        : 'incoming'
    }`;

  if (id) {
    wrap.dataset.messageId =
      id;
  }

  const bubble =
    document.createElement('div');

  bubble.className =
    'message';

  if (
    !outgoing &&
    sender
  ) {
    const senderEl =
      document.createElement('div');

    senderEl.className =
      'message-sender';

    senderEl.textContent =
      sender;

    bubble.appendChild(
      senderEl
    );
  }

  const textEl =
    document.createElement('div');

  textEl.textContent =
    text;

  bubble.appendChild(
    textEl
  );

  const meta =
    document.createElement('div');

  meta.className =
    'message-meta';

  meta.textContent =
    formatTime(timestamp);

  bubble.appendChild(
    meta
  );

  wrap.appendChild(
    bubble
  );

  $('messages')
    .appendChild(wrap);

  $('messages').scrollTop =
    $('messages').scrollHeight;
}


async function processIncomingMessage(
  payload
) {
  if (
    !payload?.U ||
    !payload?.V ||
    !payload?.nonce ||
    !payload?.ciphertext
  ) {
    throw new Error(
      'Повреждённый пакет сообщения'
    );
  }

  /*
   * Сервер положил в очередь именно
   * ciphertext для этого deviceId.
   */
  if (
    payload.deviceId &&
    payload.deviceId !== deviceId
  ) {
    throw new Error(
      'Сообщение предназначено другому устройству'
    );
  }

  const K =
    NCRLWE.decapsulate(
      privateKey,
      {
        U: payload.U,
        V: payload.V
      }
    );

  const aesKey =
    await deriveAesKey(K);

  const plaintext =
    await decryptMessage(
      aesKey,
      payload.nonce,
      payload.ciphertext
    );

  addMessage(
    plaintext,
    {
      outgoing: false,
      sender:
        payload.sender ||
        'Неизвестный',
      timestamp:
        payload.createdAt,
      id:
        `${payload.id}:${payload.deviceId || deviceId}`
    }
  );
}


async function loadHistory() {
  if (!username) return;

  try {
    const data =
      await apiGetMessages();

    const messages =
      Array.isArray(
        data.messages
      )
        ? data.messages
        : [];

    for (const payload of messages) {
      try {
        await processIncomingMessage(
          payload
        );
      } catch (error) {
        console.error(
          'History decrypt error:',
          error
        );
      }
    }
  } catch (error) {
    console.error(
      'History error:',
      error
    );

    setStatus(
      `Ошибка загрузки истории: ${error.message}`,
      true
    );
  }
}


async function checkMessages() {
  if (
    !username ||
    pollingInProgress
  ) {
    return;
  }

  pollingInProgress = true;

  try {
    const data =
      await apiGetMessages();

    const messages =
      Array.isArray(
        data.messages
      )
        ? data.messages
        : [];

    let failed = 0;

    for (
      const payload of messages
    ) {
      try {
        await processIncomingMessage(
          payload
        );
      } catch (error) {
        failed++;

        console.error(
          'Decryption error:',
          error,
          payload
        );
      }
    }

    if (failed) {
      setStatus(
        `Не удалось расшифровать: ${failed}`,
        true
      );
    } else {
      setStatus('Подключено');
    }
  } catch (error) {
    console.error(
      'Polling error:',
      error
    );

    setStatus(
      `Ошибка связи: ${error.message}`,
      true
    );
  } finally {
    pollingInProgress = false;

    if (username) {
      clearTimeout(
        pollingTimer
      );

      pollingTimer =
        setTimeout(
          checkMessages,
          3000
        );
    }
  }
}


function base64ToUint8Array(
  base64String
) {
  const padding =
    '='.repeat(
      (4 -
        (base64String.length % 4)) %
        4
    );

  const base64 =
    (
      base64String +
      padding
    )
      .replace(/-/g, '+')
      .replace(/_/g, '/');

  const rawData =
    window.atob(base64);

  return Uint8Array.from(
    [...rawData].map(
      (char) =>
        char.charCodeAt(0)
    )
  );
}


async function enableNotifications() {
  if (
    !('serviceWorker' in navigator)
  ) {
    throw new Error(
      'Service Worker не поддерживается'
    );
  }

  if (
    !('PushManager' in window)
  ) {
    throw new Error(
      'Push API не поддерживается'
    );
  }

  if (
    !('Notification' in window)
  ) {
    throw new Error(
      'Notifications API не поддерживается'
    );
  }

  const standalone =
    window.matchMedia(
      '(display-mode: standalone)'
    ).matches ||
    window.navigator.standalone === true;

  if (!standalone) {
    throw new Error(
      'Сначала добавьте NCR Messenger на экран «Домой»'
    );
  }

  const permission =
    await Notification.requestPermission();

  if (permission !== 'granted') {
    throw new Error(
      'Разрешение на уведомления не предоставлено'
    );
  }

  const registration =
    await navigator.serviceWorker.ready;

  const config =
    await apiGetPushConfig();

  const existing =
    await registration.pushManager
      .getSubscription();

  let subscription =
    existing;

  if (!subscription) {
    subscription =
      await registration.pushManager
        .subscribe({
          userVisibleOnly: true,
          applicationServerKey:
            base64ToUint8Array(
              config.publicKey
            )
        });
  }

  await apiSubscribePush(
    subscription.toJSON()
  );

  localStorage.setItem(
    `ncr_push_enabled:${deviceId}`,
    '1'
  );

  $('notification-icon')
    .textContent = '🔔';

  setStatus(
    'Уведомления включены'
  );
}


async function disableNotifications() {
  const registration =
    await navigator.serviceWorker.ready;

  const subscription =
    await registration.pushManager
      .getSubscription();

  if (subscription) {
    await apiUnsubscribePush(
      subscription.endpoint
    );

    await subscription.unsubscribe();
  }

  localStorage.removeItem(
    `ncr_push_enabled:${deviceId}`
  );

  $('notification-icon')
    .textContent = '🔕';

  setStatus(
    'Уведомления выключены'
  );
}


async function setupNotificationButton() {
  if (
    !('Notification' in window)
  ) {
    $('notification-btn')
      .classList.add('hidden');

    return;
  }

  if (
    Notification.permission ===
    'granted'
  ) {
    $('notification-icon')
      .textContent = '🔔';
  } else {
    $('notification-icon')
      .textContent = '🔕';
  }
}


$('notification-btn')
  .addEventListener(
    'click',
    async () => {
      const button =
        $('notification-btn');

      button.disabled = true;

      try {
        if (
          Notification.permission ===
          'granted'
        ) {
          await enableNotifications();
        } else {
          await enableNotifications();
        }
      } catch (error) {
        console.error(
          'Notification error:',
          error
        );

        setStatus(
          error.message,
          true
        );
      } finally {
        button.disabled = false;
      }
    }
  );


$('login-form')
  .addEventListener(
    'submit',
    async (event) => {
      event.preventDefault();

      if (authInProgress) {
        return;
      }

      const name =
        $('username-input')
          .value
          .trim();

      const password =
        $('password-input')
          .value;

      $('login-error')
        .textContent = '';

      if (!name || !password) {
        return;
      }

      authInProgress = true;

      $('login-btn').disabled =
        true;

      $('login-btn').textContent =
        'Подключение…';

      try {
        deviceId =
          getDeviceId();

        loadOrGenerateKeys(name);

        await apiAuth(
          name,
          password,
          publicKey,
          deviceId
        );

        username = name;

        localStorage.setItem(
          'ncrlwe_last_username',
          name
        );

        renderedMessageIds.clear();

        $('messages').innerHTML = `
          <div
            id="empty-state"
            class="empty-state"
          >
            <div class="empty-icon">✉</div>
            <h2>Сообщений пока нет</h2>
            <p>
              Введите имя получателя
              ниже и отправьте первое
              сообщение.
            </p>
          </div>
        `;

        showChat(name);

        await setupNotificationButton();

        await loadHistory();

        await checkMessages();
      } catch (error) {
        console.error(
          'Login error:',
          error
        );

        $('login-error')
          .textContent =
          error.message;
      } finally {
        authInProgress = false;

        $('login-btn').disabled =
          false;

        $('login-btn').textContent =
          'Войти / создать аккаунт';
      }
    }
  );


$('logout-btn')
  .addEventListener(
    'click',
    () => {
      username = null;

      clearTimeout(
        pollingTimer
      );

      pollingTimer = null;

      pollingInProgress = false;

      privateKey = null;
      publicKey = null;

      renderedMessageIds.clear();

      $('messages').innerHTML = `
        <div
          id="empty-state"
          class="empty-state"
        >
          <div class="empty-icon">✉</div>

          <h2>
            Сообщений пока нет
          </h2>

          <p>
            Введите имя получателя
            ниже и отправьте первое
            сообщение.
          </p>
        </div>
      `;

      $('login-error')
        .textContent = '';

      showLogin();
    }
  );


$('composer')
  .addEventListener(
    'submit',
    (event) => {
      event.preventDefault();

      sendMessage();
    }
  );


async function sendMessage() {
  if (!username) {
    return;
  }

  const recipient =
    $('recipient-input')
      .value
      .trim();

  const message =
    $('message-input')
      .value
      .trim();

  if (
    !recipient ||
    !message
  ) {
    return;
  }

  $('send-btn').disabled =
    true;

  setStatus(
    'Шифрование и отправка…'
  );

  try {
    const recipientDevices =
      await apiGetPublicKeys(
        recipient
      );

    if (!recipientDevices.length) {
      throw new Error(
        'У получателя нет зарегистрированных устройств'
      );
    }

    /*
     * Одно и то же сообщение
     * шифруется отдельно для каждого
     * устройства получателя.
     */
    const payloads = [];

    for (
      const device of recipientDevices
    ) {
      const {
        ciphertext,
        K
      } =
        NCRLWE.encapsulate(
          device.publicKey
        );

      const aesKey =
        await deriveAesKey(K);

      const encrypted =
        await encryptMessage(
          aesKey,
          message
        );

      payloads.push({
        deviceId:
          device.deviceId,

        payload: {
          U:
            ciphertext.U,

          V:
            ciphertext.V,

          nonce:
            encrypted.nonce,

          ciphertext:
            encrypted.ciphertext
        }
      });
    }

    const result =
      await apiSend(
        recipient,
        payloads
      );

    addMessage(
      message,
      {
        outgoing: true,
        sender: username,
        timestamp: Date.now(),
        id: `${result.id}:outgoing`
      }
    );

    $('message-input')
      .value = '';

    autoGrowTextarea();

    setStatus(
      `Отправлено пользователю ${recipient}`
    );
  } catch (error) {
    console.error(
      'Send error:',
      error
    );

    setStatus(
      `Ошибка отправки: ${error.message}`,
      true
    );
  } finally {
    $('send-btn').disabled =
      false;

    $('message-input')
      .focus();
  }
}


function autoGrowTextarea() {
  const textarea =
    $('message-input');

  textarea.style.height =
    'auto';

  textarea.style.height =
    `${Math.min(
      textarea.scrollHeight,
      120
    )}px`;
}


$('message-input')
  .addEventListener(
    'input',
    autoGrowTextarea
  );


$('message-input')
  .addEventListener(
    'keydown',
    (event) => {
      if (
        event.key === 'Enter' &&
        !event.shiftKey
      ) {
        event.preventDefault();

        sendMessage();
      }
    }
  );


deviceId =
  getDeviceId();

const lastUsername =
  localStorage.getItem(
    'ncrlwe_last_username'
  );

if (lastUsername) {
  $('username-input')
    .value = lastUsername;
}


if (
  'serviceWorker' in navigator
) {
  navigator.serviceWorker
    .register(
      '/sw.js',
      {
        updateViaCache: 'none'
      }
    )
    .then(
      (registration) => {
        registration.update()
          .catch(() => {});
      }
    )
    .catch(
      (error) =>
        console.warn(
          'Service Worker:',
          error
        )
    );
}