let username = null;
let privateKey = null;
let publicKey = null;
let pollingTimer = null;
let pollingInProgress = false;
let authInProgress = false;

const $ = (id) => document.getElementById(id);

function keyStorageName(name) {
  return `ncrlwe_keys:${name}`;
}

function loadOrGenerateKeys(name) {
  const storageKey = keyStorageName(name);
  const stored = localStorage.getItem(storageKey);

  if (stored) {
    try {
      const parsed = JSON.parse(stored);
      if (parsed?.privateKey && parsed?.publicKey) {
        privateKey = parsed.privateKey;
        publicKey = parsed.publicKey;
        return;
      }
    } catch {
      localStorage.removeItem(storageKey);
    }
  }

  const keys = NCRLWE.generateKeypair();
  privateKey = keys.privateKey;
  publicKey = keys.publicKey;
  localStorage.setItem(storageKey, JSON.stringify({ privateKey, publicKey }));
}

async function deriveAesKey(K) {
  const bytes = NCRLWE.matrixToBytes(K);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptMessage(aesKey, plaintext) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, encoded);
  return {
    nonce: Array.from(nonce),
    ciphertext: Array.from(new Uint8Array(ciphertext))
  };
}

async function decryptMessage(aesKey, nonce, ciphertext) {
  const decoded = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(nonce) },
    aesKey,
    new Uint8Array(ciphertext)
  );
  return new TextDecoder().decode(decoded);
}

async function readJsonResponse(res) {
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch {}
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function apiAuth(name, password, key) {
  const res = await fetch('/api/auth', {
    method: 'POST',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: name, password, publicKey: key })
  });
  return readJsonResponse(res);
}

async function apiGetPublicKey(name) {
  const url = `/api/publicKey?username=${encodeURIComponent(name)}&_=${Date.now()}`;
  const res = await fetch(url, { method: 'GET', cache: 'no-store' });
  const data = await readJsonResponse(res);
  return data.publicKey;
}

async function apiSend(recipient, payload) {
  const res = await fetch('/api/send', {
    method: 'POST',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sender: username, recipient, payload })
  });
  return readJsonResponse(res);
}

async function apiGetMessages(name) {
  const url = `/api/messages?username=${encodeURIComponent(name)}&_=${Date.now()}`;
  const res = await fetch(url, { method: 'GET', cache: 'no-store' });
  return readJsonResponse(res);
}

function setStatus(text, isError = false) {
  $('status-bar').textContent = text || '';
  $('status-bar').classList.toggle('error', isError);
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
  return new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit' }).format(timestamp);
}

function addMessage(text, { outgoing, sender, timestamp }) {
  const empty = $('empty-state');
  if (empty) empty.remove();

  const wrap = document.createElement('div');
  wrap.className = `message-wrap ${outgoing ? 'outgoing' : 'incoming'}`;

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
  meta.textContent = formatTime(timestamp || Date.now());
  bubble.appendChild(meta);

  wrap.appendChild(bubble);
  $('messages').appendChild(wrap);
  $('messages').scrollTop = $('messages').scrollHeight;
}

async function processIncomingMessage(payload) {
  if (!payload?.U || !payload?.V || !payload?.nonce || !payload?.ciphertext) {
    throw new Error('Получен повреждённый пакет сообщения');
  }

  const K = NCRLWE.decapsulate(privateKey, { U: payload.U, V: payload.V });
  const aesKey = await deriveAesKey(K);
  const plaintext = await decryptMessage(aesKey, payload.nonce, payload.ciphertext);

  addMessage(plaintext, {
    outgoing: false,
    sender: payload.sender || 'Неизвестный',
    timestamp: payload.createdAt
  });
}

async function checkMessages() {
  if (!username || pollingInProgress) return;

  pollingInProgress = true;
  try {
    const data = await apiGetMessages(username);
    const messages = Array.isArray(data.messages) ? data.messages : [];

    let failed = 0;
    for (const payload of messages) {
      try {
        await processIncomingMessage(payload);
      } catch (error) {
        failed++;
        console.error('Decryption error:', error, payload);
      }
    }

    setStatus(failed ? `Не удалось расшифровать: ${failed}` : 'Подключено', failed > 0);
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

async function sendMessage() {
  if (!username) return;

  const recipient = $('recipient-input').value.trim();
  const message = $('message-input').value.trim();
  if (!recipient || !message) return;

  $('send-btn').disabled = true;
  setStatus('Шифрование и отправка…');

  try {
    const recipientPub = await apiGetPublicKey(recipient);
    const { ciphertext, K } = NCRLWE.encapsulate(recipientPub);
    const aesKey = await deriveAesKey(K);
    const encrypted = await encryptMessage(aesKey, message);

    const payload = {
      U: ciphertext.U,
      V: ciphertext.V,
      nonce: encrypted.nonce,
      ciphertext: encrypted.ciphertext
    };

    await apiSend(recipient, payload);

    addMessage(message, { outgoing: true, timestamp: Date.now() });
    $('message-input').value = '';
    autoGrowTextarea();
    setStatus(`Отправлено пользователю ${recipient}`);
  } catch (error) {
    console.error('Send error:', error);
    setStatus(`Ошибка отправки: ${error.message}`, true);
  } finally {
    $('send-btn').disabled = false;
    $('message-input').focus();
  }
}

function autoGrowTextarea() {
  const textarea = $('message-input');
  textarea.style.height = 'auto';
  textarea.style.height = `${Math.min(textarea.scrollHeight, 140)}px`;
}

$('login-form').addEventListener('submit', async (event) => {
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
    loadOrGenerateKeys(name);
    await apiAuth(name, password, publicKey);

    username = name;
    localStorage.setItem('ncrlwe_last_username', name);
    showChat(name);
    await checkMessages();
  } catch (error) {
    console.error('Login error:', error);
    $('login-error').textContent = error.message;
  } finally {
    authInProgress = false;
    $('login-btn').disabled = false;
    $('login-btn').textContent = 'Войти / создать аккаунт';
  }
});

$('logout-btn').addEventListener('click', () => {
  username = null;
  clearTimeout(pollingTimer);
  pollingTimer = null;
  privateKey = null;
  publicKey = null;
  $('messages').innerHTML = `
    <div id="empty-state" class="empty-state">
      <div class="empty-icon">✉</div>
      <h2>Сообщений пока нет</h2>
      <p>Введите имя получателя ниже и отправьте первое сообщение.</p>
    </div>`;
  $('login-error').textContent = '';
  showLogin();
});

$('composer').addEventListener('submit', (event) => {
  event.preventDefault();
  sendMessage();
});

$('message-input').addEventListener('input', autoGrowTextarea);
$('message-input').addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    sendMessage();
  }
});

// Restore the last username in the form, but never auto-login without a password.
const lastUsername = localStorage.getItem('ncrlwe_last_username');
if (lastUsername) $('username-input').value = lastUsername;

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch((error) => console.warn('SW:', error));
}
