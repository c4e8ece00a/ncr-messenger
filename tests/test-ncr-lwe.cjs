const fs = require('fs');
const vm = require('vm');
const crypto = require('crypto').webcrypto;

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
const NCRLWE = context.window.NCRLWE;

if (!NCRLWE) throw new Error('NCRLWE not exported');

for (let i = 0; i < 100; i++) {
  const { publicKey, privateKey } = NCRLWE.generateKeypair();
  const { ciphertext, K } = NCRLWE.encapsulate(publicKey);
  const recovered = NCRLWE.decapsulate(privateKey, ciphertext);
  const a = JSON.stringify(K);
  const b = JSON.stringify(recovered);
  if (a !== b) {
    throw new Error(`NCR-LWE round trip failed on iteration ${i}`);
  }
}

console.log('NCR-LWE round-trip test: 100/100 OK');
