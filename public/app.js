let username = null;
let privateKey = null;
let publicKey = null;

// --- Ключи NCR-LWE ---
function loadOrGenerateKeys() {
  const stored = localStorage.getItem('ncrlwe_keys');
  if (stored) {
    const parsed = JSON.parse(stored);
    privateKey = parsed.privateKey;
    publicKey = parsed.publicKey;
  } else {
    const keys = NCRLWE.generateKeypair();
    privateKey = keys.privateKey;
    publicKey = keys.publicKey;
    localStorage.setItem('ncrlwe_keys', JSON.stringify({ privateKey, publicKey }));
  }
}

// --- AES-GCM ---
async function deriveAesKey(K) {
  const bytes = NCRLWE.matrixToBytes(K);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptMessage(aesKey, plaintext) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, encoded);
  return { nonce: Array.from(nonce), ciphertext: Array.from(new Uint8Array(ciphertext)) };
}

async function decryptMessage(aesKey, nonce, ciphertext) {
  const decoded = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(nonce) },
    aesKey,
    new Uint8Array(ciphertext)
  );
  return new TextDecoder().decode(decoded);
}

// --- API ---
async function apiAuth(username, password, publicKey, subscription) {
  const res = await fetch('/api/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, publicKey, subscription }),
  });
  if (!res.ok) {
    const errorText = await res.text();
    let errorMessage = 'Ошибка сервера';
    try {
      const errorJson = JSON.parse(errorText);
      errorMessage = errorJson.error || errorMessage;
    } catch {}
    throw new Error(errorMessage);
  }
  return res.json();
}

async function apiGetPublicKey(username) {
  const res = await fetch(`/api/publicKey?username=${encodeURIComponent(username)}`);
  if (!res.ok) {
    const errorText = await res.text();
    let errorMessage = 'Ошибка сервера';
    try {
      const errorJson = JSON.parse(errorText);
      errorMessage = errorJson.error || errorMessage;
    } catch {}
    throw new Error(errorMessage);
  }
  const data = await res.json();
  return data.publicKey;
}

async function apiSend(recipient, payload) {
  const res = await fetch('/api/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recipient, payload }),
  });
  if (!res.ok) {
    const errorText = await res.text();
    let errorMessage = 'Ошибка сервера';
    try {
      const errorJson = JSON.parse(errorText);
      errorMessage = errorJson.error || errorMessage;
    } catch {}
    throw new Error(errorMessage);
  }
  return res.json();
}

async function apiGetMessages(username) {
  const res = await fetch(`/api/messages?username=${encodeURIComponent(username)}`);
  if (!res.ok) {
    const errorText = await res.text();
    let errorMessage = 'Ошибка сервера';
    try {
      const errorJson = JSON.parse(errorText);
      errorMessage = errorJson.error || errorMessage;
    } catch {}
    throw new Error(errorMessage);
  }
  return res.json();
}

// --- Логика интерфейса ---
document.getElementById('register-btn').addEventListener('click', async () => {
  const input = document.getElementById('username-input');
  const passwordInput = document.getElementById('password-input');
  const name = input.value.trim();
  const password = passwordInput.value.trim();
  if (!name || !password) {
    document.getElementById('login-error').textContent = 'Введите имя и пароль';
    return;
  }
  try {
    loadOrGenerateKeys();
    const subscription = null; // временно отключаем push-подписку
    await apiAuth(name, password, publicKey, subscription);
    username = name;
    document.getElementById('current-user').textContent = username;
    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('chat-screen').classList.remove('hidden');
    checkMessages();
  } catch (e) {
    document.getElementById('login-error').textContent = e.message;
  }
});

document.getElementById('logout-btn').addEventListener('click', () => {
  username = null;
  document.getElementById('chat-screen').classList.add('hidden');
  document.getElementById('login-screen').classList.remove('hidden');
});

document.getElementById('send-btn').addEventListener('click', sendMessage);
document.getElementById('message-input').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') sendMessage();
});

async function sendMessage() {
  const recipient = document.getElementById('recipient-input').value.trim();
  const message = document.getElementById('message-input').value.trim();
  if (!recipient || !message) return;
  try {
    const recipientPub = await apiGetPublicKey(recipient);
    const { ciphertext, K } = NCRLWE.encapsulate(recipientPub);
    const aesKey = await deriveAesKey(K);
    const { nonce, ciphertext: encMessage } = await encryptMessage(aesKey, message);
    const payload = { U: ciphertext.U, V: ciphertext.V, nonce, ciphertext: encMessage };
    await apiSend(recipient, payload);
    document.getElementById('message-input').value = '';
    checkMessages(); // сразу проверим свои входящие
  } catch (e) {
    alert('Ошибка: ' + e.message);
  }
}

async function checkMessages() {
  if (!username) return;
  try {
    const data = await apiGetMessages(username);
    for (const payload of data.messages) {
      await processIncomingMessage(payload);
    }
  } catch (e) {
    console.error('Polling error', e);
  }
  setTimeout(checkMessages, 5000);
}

async function processIncomingMessage(payload) {
  try {
    console.log('Получено сырое сообщение:', payload);
    const K = NCRLWE.decapsulate(privateKey, { U: payload.U, V: payload.V });
    const aesKey = await deriveAesKey(K);
    const plaintext = await decryptMessage(aesKey, payload.nonce, payload.ciphertext);
    console.log('Расшифровано:', plaintext);
    const messagesDiv = document.getElementById('messages');
    const div = document.createElement('div');
    div.className = 'message';
    div.textContent = plaintext;
    messagesDiv.appendChild(div);
  } catch (e) {
    alert('Ошибка при расшифровке: ' + e.message);
    console.error('Decryption error', e);
  }
}

// Регистрируем service worker при загрузке
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js')
    .then(() => console.log('SW registered'))
    .catch(console.error);
}
