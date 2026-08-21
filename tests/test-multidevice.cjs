const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto').webcrypto;

const source = fs.readFileSync('./public/ncr-lwe.js', 'utf8');
const context = vm.createContext({
  crypto,
  window: {},
  Uint8Array,
  Uint32Array,
  Math,
  Array,
  Error
});
vm.runInContext(source, context);

const N = context.window.NCRLWE;

async function derive(K) {
  const bytes = N.matrixToBytes(K);
  return crypto.subtle.digest('SHA-256', bytes);
}

async function run() {
  for (let i = 0; i < 100; i++) {
    const a = N.generateKeypair();
    const b = N.generateKeypair();
    const c = N.generateKeypair();

    const ca = N.encapsulate(a.publicKey);
    const cb = N.encapsulate(b.publicKey);
    const cc = N.encapsulate(c.publicKey);

    const ka = await derive(N.decapsulate(a.privateKey, ca.ciphertext));
    const kb = await derive(N.decapsulate(b.privateKey, cb.ciphertext));
    const kc = await derive(N.decapsulate(c.privateKey, cc.ciphertext));

    const expectedA = await derive(ca.K);
    const expectedB = await derive(cb.K);
    const expectedC = await derive(cc.K);

    if (
      Buffer.from(ka).toString('hex') !== Buffer.from(expectedA).toString('hex') ||
      Buffer.from(kb).toString('hex') !== Buffer.from(expectedB).toString('hex') ||
      Buffer.from(kc).toString('hex') !== Buffer.from(expectedC).toString('hex')
    ) {
      throw new Error(`Multi-device key isolation failed at iteration ${i}`);
    }

    if (Buffer.from(ka).toString('hex') === Buffer.from(kb).toString('hex')) {
      throw new Error(`Independent device keys unexpectedly matched at iteration ${i}`);
    }
  }

  const auth = fs.readFileSync('./api/auth.js', 'utf8');
  const send = fs.readFileSync('./api/send.js', 'utf8');
  const messages = fs.readFileSync('./api/messages.js', 'utf8');
  const pub = fs.readFileSync('./api/publicKey.js', 'utf8');

  if (!auth.includes('device:${username}:${deviceId}')) throw new Error('Device registry missing');
  if (!send.includes('messages:${recipient}:${envelope.deviceId}')) throw new Error('Per-device queues missing');
  if (!messages.includes('messages:${session.username}:${session.deviceId}')) throw new Error('Session device queue missing');
  if (!pub.includes('devices:${username}')) throw new Error('Multi-device public key lookup missing');

  console.log('Multi-device encryption isolation test: 100/100 OK');
}

run().catch(error => {
  console.error(error);
  process.exit(1);
});
