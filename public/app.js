let username = null;
let privateKey = null;
let publicKey = null;

let pollingTimer = null;
let pollingInProgress = false;
let sending = false;

const POLL_INTERVAL = 5000;

/* =========================================================
   DOM
========================================================= */

const loginScreen =
  document.getElementById('login-screen');

const chatScreen =
  document.getElementById('chat-screen');

const usernameInput =
  document.getElementById('username-input');

const passwordInput =
  document.getElementById('password-input');

const registerBtn =
  document.getElementById('register-btn');

const loginError =
  document.getElementById('login-error');

const currentUser =
  document.getElementById('current-user');

const logoutBtn =
  document.getElementById('logout-btn');

const recipientInput =
  document.getElementById('recipient-input');

const messageInput =
  document.getElementById('message-input');

const sendBtn =
  document.getElementById('send-btn');

const refreshBtn =
  document.getElementById('refresh-btn');

const messagesDiv =
  document.getElementById('messages');

const chatStatus =
  document.getElementById('chat-status');

/* =========================================================
   Helpers
========================================================= */

function showLoginError(message) {
  loginError.textContent = message || '';
}

function setChatStatus(message) {
  if (chatStatus) {
    chatStatus.textContent = message || '';
  }
}

function scrollMessagesToBottom() {
  messagesDiv.scrollTop =
    messagesDiv.scrollHeight;
}

function setSendingState(value) {
  sending = value;

  sendBtn.disabled = value;

  sendBtn.textContent =
    value ? 'Отправка…' : 'Отправить';
}

/* =========================================================
   KEY STORAGE
========================================================= */

/*
 * ВАЖНО:
 *
 * Старый код использовал:
 *
 * ncrlwe_keys
 *
 * для всех пользователей.
 *
 * Теперь ключ зависит от username.
 */

function getKeyStorageName(name) {
  return `ncrlwe_keys:${name}`;
}

function loadOrGenerateKeys(name) {
  const storageName =
    getKeyStorageName(name);

  const stored =
    localStorage.getItem(storageName);

  if (stored) {
    try {
      const parsed =
        JSON.parse(stored);

      if (
        parsed &&
        parsed.privateKey &&
        parsed.publicKey
      ) {
        privateKey =
          parsed.privateKey;

        publicKey =
          parsed.publicKey;

        return;
      }
    } catch (error) {
      console.error(
        'Ошибка чтения ключей:',
        error
      );
    }

    localStorage.removeItem(
      storageName
    );
  }

  const keys =
    NCRLWE.generateKeypair();

  privateKey =
    keys.privateKey;

  publicKey =
    keys.publicKey;

  localStorage.setItem(
    storageName,
    JSON.stringify({
      privateKey,
      publicKey
    })
  );
}

/* =========================================================
   AES-GCM
========================================================= */

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
  if (
    !Array.isArray(nonce) ||
    !Array.isArray(ciphertext)
  ) {
    throw new Error(
      'Повреждённый формат сообщения'
    );
  }

  const decoded =
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: new Uint8Array(nonce)
      },
      aesKey,
      new Uint8Array(ciphertext)
    );

  return new TextDecoder().decode(
    decoded
  );
}

/* =========================================================
   API
========================================================= */

async function parseApiError(res) {
  const text =
    await res.text();

  try {
    const json =
      JSON.parse(text);

    return (
      json.error ||
      `Ошибка HTTP ${res.status}`
    );
  } catch {
    return (
      text ||
      `Ошибка HTTP ${res.status}`
    );
  }
}

async function apiAuth(
  username,
  password,
  publicKey
) {
  const res =
    await fetch('/api/auth', {
      method: 'POST',
      headers: {
        'Content-Type':
          'application/json'
      },
      body: JSON.stringify({
        username,
        password,
        publicKey
      })
    });

  if (!res.ok) {
    throw new Error(
      await parseApiError(res)
    );
  }

  return res.json();
}

async function apiGetPublicKey(name) {
  const res =
    await fetch(
      `/api/publicKey?username=${encodeURIComponent(name)}`
    );

  if (!res.ok) {
    throw new Error(
      await parseApiError(res)
    );
  }

  const data =
    await res.json();

  return data.publicKey;
}

async function apiSend(
  sender,
  recipient,
  payload
) {
  const res =
    await fetch('/api/send', {
      method: 'POST',
      headers: {
        'Content-Type':
          'application/json'
      },
      body: JSON.stringify({
        sender,
        recipient,
        payload
      })
    });

  if (!res.ok) {
    throw new Error(
      await parseApiError(res)
    );
  }

  return res.json();
}

async function apiGetMessages(name) {
  const res =
    await fetch(
      `/api/messages?username=${encodeURIComponent(name)}`,
      {
        cache: 'no-store'
      }
    );

  if (!res.ok) {
    throw new Error(
      await parseApiError(res)
    );
  }

  return res.json();
}

async function apiAck(
  name,
  messageId
) {
  const res =
    await fetch('/api/ack', {
      method: 'POST',
      headers: {
        'Content-Type':
          'application/json'
      },
      body: JSON.stringify({
        username: name,
        messageId
      })
    });

  if (!res.ok) {
    throw new Error(
      await parseApiError(res)
    );
  }

  return res.json();
}

/* =========================================================
   LOGIN
========================================================= */

registerBtn.addEventListener(
  'click',
  login
);

passwordInput.addEventListener(
  'keydown',
  event => {
    if (event.key === 'Enter') {
      login();
    }
  }
);

usernameInput.addEventListener(
  'keydown',
  event => {
    if (event.key === 'Enter') {
      passwordInput.focus();
    }
  }
);

async function login() {
  const name =
    usernameInput.value.trim();

  const password =
    passwordInput.value;

  showLoginError('');

  if (!name || !password) {
    showLoginError(
      'Введите имя и пароль'
    );
    return;
  }

  registerBtn.disabled = true;
  registerBtn.textContent =
    'Подключение…';

  try {
    /*
     * Сначала загружаем локальную пару ключей.
     */
    loadOrGenerateKeys(name);

    /*
     * Сервер проверит:
     *
     * новый аккаунт -> зарегистрировать
     *
     * существующий аккаунт ->
     * проверить пароль и совпадение publicKey
     */
    const result =
      await apiAuth(
        name,
        password,
        publicKey
      );

    username =
      result.username || name;

    currentUser.textContent =
      username;

    loginScreen.classList.add(
      'hidden'
    );

    chatScreen.classList.remove(
      'hidden'
    );

    setChatStatus(
      'Подключено'
    );

    recipientInput.focus();

    startPolling();

    await checkMessages();

  } catch (error) {
    console.error(
      'LOGIN ERROR:',
      error
    );

    showLoginError(
      error.message
    );

  } finally {
    registerBtn.disabled = false;
    registerBtn.textContent =
      'Войти / Регистрация';
  }
}

/* =========================================================
   LOGOUT
========================================================= */

logoutBtn.addEventListener(
  'click',
  logout
);

function logout() {
  stopPolling();

  username = null;
  privateKey = null;
  publicKey = null;

  chatScreen.classList.add(
    'hidden'
  );

  loginScreen.classList.remove(
    'hidden'
  );

  usernameInput.value = '';
  passwordInput.value = '';

  messagesDiv.innerHTML = '';

  setChatStatus('');
  showLoginError('');

  usernameInput.focus();
}

/* =========================================================
   SEND
========================================================= */

sendBtn.addEventListener(
  'click',
  sendMessage
);

messageInput.addEventListener(
  'keydown',
  event => {

    /*
     * Enter отправляет.
     *
     * Shift + Enter:
     * новая строка.
     */
    if (
      event.key === 'Enter' &&
      !event.shiftKey
    ) {
      event.preventDefault();
      sendMessage();
    }
  }
);

async function sendMessage() {
  if (sending) {
    return;
  }

  const recipient =
    recipientInput.value.trim();

  const message =
    messageInput.value.trim();

  if (!recipient) {
    recipientInput.focus();
    return;
  }

  if (!message) {
    messageInput.focus();
    return;
  }

  if (!username) {
    return;
  }

  setSendingState(true);

  try {
    setChatStatus(
      `Получаем ключ ${recipient}…`
    );

    const recipientPub =
      await apiGetPublicKey(
        recipient
      );

    /*
     * Создаём уникальный сеансовый ключ.
     */
    const {
      ciphertext,
      K
    } = NCRLWE.encapsulate(
      recipientPub
    );

    const aesKey =
      await deriveAesKey(K);

    const encrypted =
      await encryptMessage(
        aesKey,
        message
      );

    const payload = {
      U: ciphertext.U,
      V: ciphertext.V,
      nonce: encrypted.nonce,
      ciphertext:
        encrypted.ciphertext
    };

    setChatStatus(
      'Отправляем…'
    );

    const result =
      await apiSend(
        username,
        recipient,
        payload
      );

    /*
     * Показываем исходящее сообщение
     * сразу, не ожидая polling.
     */
    addMessageToChat({
      id: result.id,
      sender: username,
      recipient,
      text: message,
      outgoing: true,
      createdAt: Date.now()
    });

    messageInput.value = '';

    setChatStatus(
      'Доставлено на сервер'
    );

    scrollMessagesToBottom();

  } catch (error) {
    console.error(
      'SEND ERROR:',
      error
    );

    setChatStatus(
      'Ошибка отправки'
    );

    addSystemMessage(
      `Ошибка отправки: ${error.message}`
    );

  } finally {
    setSendingState(false);

    messageInput.focus();
  }
}

/* =========================================================
   POLLING
========================================================= */

function startPolling() {
  stopPolling();

  pollingTimer =
    setInterval(
      checkMessages,
      POLL_INTERVAL
    );
}

function stopPolling() {
  if (pollingTimer) {
    clearInterval(
      pollingTimer
    );

    pollingTimer = null;
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
      await apiGetMessages(
        username
      );

    for (
      const message
      of data.messages || []
    ) {
      await processIncomingMessage(
        message
      );
    }

    if (
      (data.messages || []).length > 0
    ) {
      setChatStatus(
        'Сообщения обновлены'
      );
    }

  } catch (error) {
    console.error(
      'POLLING ERROR:',
      error
    );

    setChatStatus(
      'Нет связи с сервером'
    );

  } finally {
    pollingInProgress = false;
  }
}

/* =========================================================
   RECEIVE MESSAGE
========================================================= */

async function processIncomingMessage(
  message
) {
  /*
   * Проверяем, не отображали ли
   * уже это сообщение.
   */
  const existing =
    document.querySelector(
      `[data-message-id="${CSS.escape(message.id)}"]`
    );

  if (existing) {
    /*
     * Если оно уже есть на экране,
     * подтверждаем его.
     */
    try {
      await apiAck(
        username,
        message.id
      );
    } catch (error) {
      console.error(
        'ACK ERROR:',
        error
      );
    }

    return;
  }

  try {
    console.log(
      'Получено сообщение:',
      message
    );

    if (
      !message.payload
    ) {
      throw new Error(
        'У сообщения отсутствует payload'
      );
    }

    const payload =
      message.payload;

    /*
     * 1. NCR-LWE
     */
    const K =
      NCRLWE.decapsulate(
        privateKey,
        {
          U: payload.U,
          V: payload.V
        }
      );

    /*
     * 2. Получаем AES ключ
     */
    const aesKey =
      await deriveAesKey(K);

    /*
     * 3. AES-GCM
     */
    const plaintext =
      await decryptMessage(
        aesKey,
        payload.nonce,
        payload.ciphertext
      );

    /*
     * Только теперь считаем сообщение
     * успешно доставленным.
     */
    addMessageToChat({
      id: message.id,
      sender: message.sender,
      recipient: message.recipient,
      text: plaintext,
      outgoing:
        message.sender === username,
      createdAt:
        message.createdAt
    });

    /*
     * Подтверждаем серверу успешную
     * обработку.
     */
    await apiAck(
      username,
      message.id
    );

    console.log(
      'Сообщение успешно расшифровано:',
      plaintext
    );

    scrollMessagesToBottom();

  } catch (error) {
    /*
     * ВАЖНО:
     *
     * ACK здесь НЕ вызываем.
     *
     * Сообщение останется в Redis
     * и будет повторно доступно.
     */
    console.error(
      'DECRYPTION ERROR:',
      error,
      message
    );

    addSystemMessage(
      `Не удалось расшифровать сообщение от ${message.sender || 'неизвестного пользователя'}: ${error.message}`
    );
  }
}

/* =========================================================
   UI
========================================================= */

function formatTime(timestamp) {
  if (!timestamp) {
    return '';
  }

  return new Date(
    timestamp
  ).toLocaleTimeString(
    [],
    {
      hour: '2-digit',
      minute: '2-digit'
    }
  );
}

function addMessageToChat({
  id,
  sender,
  text,
  outgoing,
  createdAt
}) {
  /*
   * Не добавляем дубликаты.
   */
  if (
    document.querySelector(
      `[data-message-id="${CSS.escape(id)}"]`
    )
  ) {
    return;
  }

  const wrapper =
    document.createElement(
      'div'
    );

  wrapper.className =
    outgoing
      ? 'message-row outgoing'
      : 'message-row incoming';

  wrapper.dataset.messageId =
    id;

  const bubble =
    document.createElement(
      'div'
    );

  bubble.className =
    'message';

  const senderElement =
    document.createElement(
      'div'
    );

  senderElement.className =
    'message-sender';

  senderElement.textContent =
    outgoing
      ? 'Вы'
      : sender || 'Пользователь';

  const textElement =
    document.createElement(
      'div'
    );

  textElement.className =
    'message-text';

  /*
   * textContent, а не innerHTML.
   *
   * Это важно для защиты от HTML/JS
   * внутри сообщения.
   */
  textElement.textContent =
    text;

  const timeElement =
    document.createElement(
      'div'
    );

  timeElement.className =
    'message-time';

  timeElement.textContent =
    formatTime(createdAt);

  bubble.appendChild(
    senderElement
  );

  bubble.appendChild(
    textElement
  );

  bubble.appendChild(
    timeElement
  );

  wrapper.appendChild(
    bubble
  );

  messagesDiv.appendChild(
    wrapper
  );

  scrollMessagesToBottom();
}

function addSystemMessage(text) {
  const div =
    document.createElement(
      'div'
    );

  div.className =
    'system-message';

  div.textContent =
    text;

  messagesDiv.appendChild(
    div
  );

  scrollMessagesToBottom();
}

/* =========================================================
   REFRESH
========================================================= */

if (refreshBtn) {
  refreshBtn.addEventListener(
    'click',
    async () => {
      await checkMessages();
    }
  );
}

/* =========================================================
   SERVICE WORKER
========================================================= */

if (
  'serviceWorker' in navigator
) {
  window.addEventListener(
    'load',
    () => {
      navigator.serviceWorker
        .register('/sw.js')
        .then(
          registration => {
            console.log(
              'Service Worker registered:',
              registration.scope
            );
          }
        )
        .catch(error => {
          console.error(
            'Service Worker error:',
            error
          );
        });
    }
  );
}
