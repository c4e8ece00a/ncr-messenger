let username = null;
let deviceId = null;
let privateKey = null;
let publicKey = null;

let pollingTimer = null;
let pollingInProgress = false;
let authInProgress = false;
let notificationInProgress = false;

const renderedMessageIds = new Set();

const $ = id =>
  document.getElementById(id);


/*
 * ==========================================
 * LOCAL KEY STORAGE
 * ==========================================
 */

function keyStorageName(name) {
  return `ncrlwe_keys:${name}`;
}

function deviceStorageName(name) {
  return `ncrlwe_device:${name}`;
}

function getOrCreateDeviceId(name) {
  const key = deviceStorageName(name);
  const stored = localStorage.getItem(key);

  if (
    stored &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(stored)
  ) {
    return stored;
  }

  const generated = crypto.randomUUID();
  localStorage.setItem(key, generated);
  return generated;
}


function loadOrGenerateKeys(name) {
  const storageKey =
    keyStorageName(name);

  const stored =
    localStorage.getItem(storageKey);

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


/*
 * ==========================================
 * AES-GCM
 * ==========================================
 */

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
    nonce:
      Array.from(nonce),

    ciphertext:
      Array.from(
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
        iv:
          new Uint8Array(nonce)
      },
      aesKey,
      new Uint8Array(ciphertext)
    );

  return new TextDecoder()
    .decode(decoded);
}


/*
 * ==========================================
 * HTTP HELPERS
 * ==========================================
 */

async function readJsonResponse(res) {
  const text =
    await res.text();

  let data = {};

  try {
    data =
      text
        ? JSON.parse(text)
        : {};
  } catch {
    data = {};
  }

  if (!res.ok) {
    throw new Error(
      data.error ||
      `HTTP ${res.status}`
    );
  }

  return data;
}


/*
 * ==========================================
 * AUTH API
 * ==========================================
 */

async function apiAuth(
  name,
  password,
  key,
  currentDeviceId
) {
  const res =
    await fetch(
      '/api/auth',
      {
        method: 'POST',
        cache: 'no-store',
        credentials: 'same-origin',
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
      }
    );

  return readJsonResponse(res);
}


/*
 * ==========================================
 * PUBLIC KEY API
 * ==========================================
 */

async function apiGetRecipientDevices(name) {
  const url = `/api/publicKey?username=${encodeURIComponent(name)}&_=${Date.now()}`;
  const res = await fetch(url, {
    method: 'GET',
    cache: 'no-store',
    credentials: 'same-origin'
  });

  const data = await readJsonResponse(res);
  return Array.isArray(data.devices) ? data.devices : [];
}

/*
 * ==========================================
 * SEND MESSAGE API
 * ==========================================
 */

async function apiSend(
  recipient,
  payload
) {
  const res =
    await fetch(
      '/api/send',
      {
        method: 'POST',
        cache: 'no-store',
        credentials: 'same-origin',
        headers: {
          'Content-Type':
            'application/json'
        },
        body:
          JSON.stringify({
            recipient,
            payload
          })
      }
    );

  return readJsonResponse(res);
}


/*
 * ==========================================
 * MESSAGES API
 * ==========================================
 */

async function apiGetMessages() {
  if (!username) throw new Error('Пользователь не авторизован');

  const url = `/api/messages?_=${Date.now()}`;
  const res = await fetch(url, {
    method: 'GET',
    cache: 'no-store',
    credentials: 'same-origin'
  });

  return readJsonResponse(res);
}


/*
 * ==========================================
 * PUSH CONFIG API
 * ==========================================
 */

async function apiGetPushConfig() {
  const res =
    await fetch(
      '/api/push/config',
      {
        method: 'GET',
        cache: 'no-store',
        credentials: 'same-origin'
      }
    );

  return readJsonResponse(res);
}


/*
 * ==========================================
 * PUSH SUBSCRIBE API
 * ==========================================
 */

async function apiSubscribePush(subscription) {
  const res = await fetch('/api/push/subscribe', {
    method: 'POST',
    cache: 'no-store',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subscription })
  });

  return readJsonResponse(res);
}

/*
 * ==========================================
 * PUSH UNSUBSCRIBE API
 * ==========================================
 */

async function apiUnsubscribePush() {
  const res = await fetch('/api/push/unsubscribe', {
    method: 'POST',
    cache: 'no-store',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({})
  });

  return readJsonResponse(res);
}

/*
 * ==========================================
 * UI
 * ==========================================
 */

function setStatus(text, isError = false) {
  const status = $('status-bar');
  if (!status) return;

  status.textContent = text || '';
  status.classList.toggle('error', isError);
}

function showChat(name) {
  $('current-user').textContent = name;
  $('user-avatar').textContent = name.charAt(0).toUpperCase();
  $('login-screen').classList.add('hidden');
  $('chat-screen').classList.remove('hidden');
  setStatus('Подключено');
}

function showLogin() {
  $('chat-screen').classList.add('hidden');
  $('login-screen').classList.remove('hidden');
}

function formatTime(timestamp) {
  if (!timestamp) return '';

  return new Intl.DateTimeFormat('ru-RU', {
    hour: '2-digit',
    minute: '2-digit'
  }).format(new Date(timestamp));
}


/*
 * ==========================================
 * MESSAGE RENDERING
 * ==========================================
 */

function resetMessageView() {
  renderedMessageIds.clear();

  $('messages').innerHTML = `
    <div id="empty-state" class="empty-state">
      <div class="empty-icon">✉</div>
      <h2>Сообщений пока нет</h2>
      <p>Введите имя получателя ниже и отправьте первое сообщение.</p>
    </div>
  `;
}

function addMessage(text, { outgoing, sender, timestamp, id }) {
  if (id && renderedMessageIds.has(id)) return;
  if (id) renderedMessageIds.add(id);

  const empty = $('empty-state');
  if (empty) empty.remove();

  const wrap = document.createElement('div');
  wrap.className = `message-wrap ${outgoing ? 'outgoing' : 'incoming'}`;
  if (id) wrap.dataset.messageId = id;

  const bubble = document.createElement('div');
  bubble.className = 'message';

  if (!outgoing && sender) {
    const senderEl = document.createElement('div');
    senderEl.className = 'message-sender';
    senderEl.textContent = sender;
    bubble.appendChild(senderEl);
  }

  const textEl = document.createElement('div');
  textEl.textContent = text;
  bubble.appendChild(textEl);

  const meta = document.createElement('div');
  meta.className = 'message-meta';
  meta.textContent = formatTime(timestamp);
  bubble.appendChild(meta);

  wrap.appendChild(bubble);
  $('messages').appendChild(wrap);
  $('messages').scrollTop = $('messages').scrollHeight;
}

function validateIncomingPayload(payload) {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Повреждённый пакет сообщения');
  }

  if (payload.deviceId !== deviceId) {
    throw new Error('Сообщение адресовано другому устройству');
  }

  if (
    !Array.isArray(payload.U) ||
    !Array.isArray(payload.V) ||
    !Array.isArray(payload.nonce) ||
    !Array.isArray(payload.ciphertext)
  ) {
    throw new Error('Повреждённый encrypted payload');
  }
}


/*
 * ==========================================
 * MESSAGE DECRYPTION
 * ==========================================
 */

async function processIncomingMessage(payload) {
  validateIncomingPayload(payload);

  if (!privateKey) throw new Error('Приватный ключ отсутствует');

  const K = NCRLWE.decapsulate(privateKey, {
    U: payload.U,
    V: payload.V
  });

  const aesKey = await deriveAesKey(K);
  const plaintext = await decryptMessage(
    aesKey,
    payload.nonce,
    payload.ciphertext
  );

  addMessage(plaintext, {
    outgoing: false,
    sender: payload.sender || 'Неизвестный',
    timestamp: payload.createdAt,
    id: payload.id
  });
}


/*
 * ==========================================
 * HISTORY
 * ==========================================
 */

async function loadHistory() {
  if (!username) return;

  try {
    const data = await apiGetMessages();
    const messages = Array.isArray(data.messages) ? data.messages : [];

    for (const payload of messages) {
      try {
        await processIncomingMessage(payload);
      } catch (error) {
        console.error('History decrypt error:', error, payload);
      }
    }
  } catch (error) {
    console.error('History error:', error);
    setStatus(`Ошибка загрузки истории: ${error.message}`, true);
  }
}


/*
 * ==========================================
 * POLLING
 * ==========================================
 */

async function checkMessages() {
  if (!username || pollingInProgress) return;

  pollingInProgress = true;

  try {
    const data = await apiGetMessages();
    const messages = Array.isArray(data.messages) ? data.messages : [];
    let failed = 0;

    for (const payload of messages) {
      if (payload?.id && renderedMessageIds.has(payload.id)) continue;

      try {
        await processIncomingMessage(payload);
      } catch (error) {
        failed++;
        console.error('Decryption error:', error, payload);
      }
    }

    if (failed > 0) {
      setStatus(`Не удалось расшифровать: ${failed}`, true);
    } else {
      setStatus('Подключено');
    }
  } catch (error) {
    console.error('Polling error:', error);
    setStatus(`Ошибка связи: ${error.message}`, true);
  } finally {
    pollingInProgress = false;

    if (username) {
      clearTimeout(pollingTimer);
      pollingTimer = setTimeout(checkMessages, 3000);
    }
  }
}


/*
 * ==========================================
 * BASE64URL
 * ==========================================
 */

function base64ToUint8Array(base64String) {
  if (typeof base64String !== 'string') {
    throw new Error('Некорректный VAPID public key');
  }

  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding)
    .replace(/-/g, '+')
    .replace(/_/g, '/');

  const rawData = window.atob(base64);
  return Uint8Array.from([...rawData].map(char => char.charCodeAt(0)));
}


/*
 * ==========================================
 * PUSH / PWA DETECTION
 * ==========================================
 */

function isStandaloneMode() {
  return (
    window.matchMedia('(display-mode: standalone)').matches ||
    window.navigator.standalone === true
  );
}

function pushSupported() {
  return (
    'serviceWorker' in navigator &&
    'PushManager' in window &&
    'Notification' in window
  );
}

async function enableNotifications() {
  if (!pushSupported()) {
    throw new Error('Push-уведомления не поддерживаются этим браузером');
  }

  if (!isStandaloneMode()) {
    throw new Error('Для уведомлений на iPhone откройте NCR Messenger с экрана «Домой»');
  }

  if (notificationInProgress) return;
  notificationInProgress = true;

  try {
    let permission = Notification.permission;

    if (permission !== 'granted') {
      permission = await Notification.requestPermission();
    }

    if (permission !== 'granted') {
      throw new Error('Разрешение на уведомления не предоставлено');
    }

    const registration = await navigator.serviceWorker.ready;
    const config = await apiGetPushConfig();

    if (!config?.publicKey) {
      throw new Error('Сервер не вернул VAPID public key');
    }

    let subscription = await registration.pushManager.getSubscription();

    if (!subscription) {
      subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: base64ToUint8Array(config.publicKey)
      });
    }

    await apiSubscribePush(subscription.toJSON());
    localStorage.setItem('ncr_push_enabled', '1');
    $('notification-icon').textContent = '🔔';
    setStatus('Уведомления включены');
  } finally {
    notificationInProgress = false;
  }
}


/*
 * ==========================================
 * DISABLE NOTIFICATIONS
 * ==========================================
 */

async function disableNotifications() {
  if (!pushSupported()) return;

  const registration = await navigator.serviceWorker.ready;
  const subscription = await registration.pushManager.getSubscription();

  if (subscription) {
    try {
      await apiUnsubscribePush();
    } catch (error) {
      console.error('Push unsubscribe server error:', error);
    }

    try {
      await subscription.unsubscribe();
    } catch (error) {
      console.error('Push unsubscribe browser error:', error);
    }
  }

  localStorage.removeItem('ncr_push_enabled');
  $('notification-icon').textContent = '🔕';
  setStatus('Уведомления выключены');
}

/*
 * ==========================================
 * CHECK PUSH STATE
 * ==========================================
 */

async function setupNotificationButton() {
  const button = $('notification-btn');
  const icon = $('notification-icon');

  if (!button || !icon) return;

  if (!pushSupported()) {
    button.classList.add('hidden');
    return;
  }

  button.classList.remove('hidden');

  if (Notification.permission === 'denied') {
    icon.textContent = '🔕';
    return;
  }

  try {
    const registration = await navigator.serviceWorker.ready;
    const subscription = await registration.pushManager.getSubscription();
    icon.textContent = subscription ? '🔔' : '🔕';
  } catch (error) {
    console.error('Push state error:', error);
    icon.textContent = '🔕';
  }
}

$('notification-btn').addEventListener('click', async () => {
  const button = $('notification-btn');
  if (button.disabled) return;

  button.disabled = true;

  try {
    await enableNotifications();
  } catch (error) {
    console.error('Notification error:', error);
    setStatus(error.message, true);
  } finally {
    button.disabled = false;
  }
});

$('login-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (authInProgress) return;

  const name = $('username-input').value.trim();
  const password = $('password-input').value;

  $('login-error').textContent = '';
  if (!name || !password) return;

  authInProgress = true;
  $('login-btn').disabled = true;
  $('login-btn').textContent = 'Подключение…';

  try {
    deviceId = getOrCreateDeviceId(name);
    loadOrGenerateKeys(name);

    await apiAuth(name, password, publicKey, deviceId);

    username = name;
    localStorage.setItem('ncrlwe_last_username', name);
    resetMessageView();
    showChat(name);
    await setupNotificationButton();
    await loadHistory();
    await checkMessages();

    if (
      pushSupported() &&
      isStandaloneMode() &&
      Notification.permission === 'granted'
    ) {
      try {
        await enableNotifications();
      } catch (pushError) {
        console.warn('Automatic push registration failed:', pushError);
      }
    }
  } catch (error) {
    console.error('Login error:', error);
    $('login-error').textContent = error.message;
    username = null;
    deviceId = null;
    privateKey = null;
    publicKey = null;
  } finally {
    authInProgress = false;
    $('login-btn').disabled = false;
    $('login-btn').textContent = 'Войти / создать аккаунт';
  }
});

$('logout-btn').addEventListener('click', async () => {
  try {
    if (pushSupported()) {
      const registration = await navigator.serviceWorker.ready;
      const subscription = await registration.pushManager.getSubscription();
      if (subscription) await apiUnsubscribePush();
    }
  } catch (error) {
    console.warn('Logout push cleanup:', error);
  }

  username = null;
  deviceId = null;
  clearTimeout(pollingTimer);
  pollingTimer = null;
  pollingInProgress = false;
  privateKey = null;
  publicKey = null;
  renderedMessageIds.clear();
  resetMessageView();
  $('login-error').textContent = '';
  showLogin();
});

$('composer').addEventListener('submit', event => {
  event.preventDefault();
  sendMessage();
});


/*
 * ==========================================
 * SEND MESSAGE
 * ==========================================
 */

async function sendMessage() {
  if (!username || !deviceId) return;

  const recipient = $('recipient-input').value.trim();
  const message = $('message-input').value.trim();

  if (!recipient || !message) return;

  $('send-btn').disabled = true;
  setStatus('Шифрование и отправка…');

  try {
    const recipientDevices = await apiGetRecipientDevices(recipient);

    if (recipientDevices.length === 0) {
      throw new Error('У получателя нет зарегистрированных устройств. Пусть он войдёт в аккаунт хотя бы на одном устройстве.');
    }

    const envelopes = [];

    for (const device of recipientDevices) {
      if (!device?.deviceId || !device?.publicKey) continue;

      const { ciphertext, K } = NCRLWE.encapsulate(device.publicKey);
      const aesKey = await deriveAesKey(K);
      const encrypted = await encryptMessage(aesKey, message);

      envelopes.push({
        deviceId: device.deviceId,
        U: ciphertext.U,
        V: ciphertext.V,
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext
      });
    }

    if (envelopes.length === 0) {
      throw new Error('Не удалось подготовить ключи устройств получателя');
    }

    const result = await apiSend(recipient, { envelopes });

    addMessage(message, {
      outgoing: true,
      sender: username,
      timestamp: Date.now(),
      id: result.id
    });

    $('message-input').value = '';
    autoGrowTextarea();

    setStatus(`Сообщение отправлено пользователю ${recipient}`);
  } catch (error) {
    console.error('Send error:', error);
    setStatus(`Ошибка отправки: ${error.message}`, true);
  } finally {
    $('send-btn').disabled = false;
    $('message-input').focus();
  }
}


/*
 * ==========================================
 * TEXTAREA
 * ==========================================
 */

function autoGrowTextarea() {
  const textarea = $('message-input');
  textarea.style.height = 'auto';
  textarea.style.height = `${Math.min(textarea.scrollHeight, 120)}px`;
}

$('message-input').addEventListener('input', autoGrowTextarea);

$('message-input').addEventListener('keydown', event => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    sendMessage();
  }
});

const lastUsername = localStorage.getItem('ncrlwe_last_username');
if (lastUsername) $('username-input').value = lastUsername;

if ('serviceWorker' in navigator) {
  navigator.serviceWorker
    .register('/sw.js')
    .then(registration => {
      console.log('Service Worker registered:', registration.scope);
    })
    .catch(error => {
      console.warn('Service Worker:', error);
    });
}
