const fs = require('fs');
const vm = require('vm');
const crypto = require('crypto').webcrypto;

const source = fs.readFileSync('./public/ncr-lwe.js', 'utf8');
const context = vm.createContext({ crypto, window: {}, Uint8Array, Uint32Array, Math, Array, Error });
vm.runInContext(source, context);
const N = context.window.NCRLWE;

async function run() {
  const messages = ['Привет', 'Hello', 'Сообщение с emoji 🔐', 'line 1\nline 2'];
  for (let i = 0; i < 100; i++) {
    const { publicKey, privateKey } = N.generateKeypair();
    const { ciphertext, K } = N.encapsulate(publicKey);
    const recovered = N.decapsulate(privateKey, ciphertext);
    const keyBytes = N.matrixToBytes(K);
    const recoveredBytes = N.matrixToBytes(recovered);
    const h1 = await crypto.subtle.digest('SHA-256', keyBytes);
    const h2 = await crypto.subtle.digest('SHA-256', recoveredBytes);
    if (Buffer.from(h1).toString('hex') !== Buffer.from(h2).toString('hex')) throw new Error('Key mismatch');

    const aesKey = await crypto.subtle.importKey('raw', h1, 'AES-GCM', false, ['encrypt', 'decrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const msg = messages[i % messages.length];
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(msg));
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
    if (new TextDecoder().decode(pt) !== msg) throw new Error('AES mismatch');
  }
  console.log('NCR-LWE + AES-GCM end-to-end test: 100/100 OK');
}
run().catch((e) => { console.error(e); process.exit(1); });
