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
async function apiRegister(username, publicKey, subscription) {
  const res = await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, publicKey, subscription }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function apiGetPublicKey(username) {
  const res = await fetch(`/api/publicKey?username=${encodeURIComponent(username)}`);
  if (!res.ok) throw new Error(await res.text());
  const data = await res.json();
  return data.publicKey;
}

async function apiSend(recipient, payload) {
  const res = await fetch('/api/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recipient, payload }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function apiGetMessages(username) {
  const res = await fetch(`/api/messages?username=${encodeURIComponent(username)}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

// --- Push-подписка ---
async function subscribeForPush() {
  if ('serviceWorker' in navigator && 'PushManager' in window) {
    try {
      const registration = await navigator.serviceWorker.ready;
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') return null;
      const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array('YOUR_VAPID_PUBLIC_KEY'), // замените
      });
      return subscription;
    } catch (e) {
      console.error('Push subscription failed', e);
      return null;
    }
  }
  return null;
}

function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) outputArray[i] = rawData.charCodeAt(i);
  return outputArray;
}

// --- Логика интерфейса ---
document.getElementById('register-btn').addEventListener('click', async () => {
  const input = document.getElementById('username-input');
  const name = input.value.trim();
  if (!name) return;
  try {
    loadOrGenerateKeys();
    const subscription = await subscribeForPush();
    await apiRegister(name, publicKey, subscription);
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
    const K = NCRLWE.decapsulate(privateKey, { U: payload.U, V: payload.V });
    const aesKey = await deriveAesKey(K);
    const plaintext = await decryptMessage(aesKey, payload.nonce, payload.ciphertext);
    const messagesDiv = document.getElementById('messages');
    const div = document.createElement('div');
    div.className = 'message';
    div.textContent = plaintext;
    messagesDiv.appendChild(div);
  } catch (e) {
    console.error('Decryption error', e);
  }
}

// Регистрируем service worker при загрузке
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js')
    .then(() => console.log('SW registered'))
    .catch(console.error);
}