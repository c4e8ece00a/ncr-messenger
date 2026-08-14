// Параметры NCR-LWE (ДЕМО – НЕ ДЛЯ ПРОДАКШЕНА!)
// Для реальной защиты увеличьте N до 256+ и Q до 65536
const N = 256;
const Q = 65536;
const SMALL_BOUND = 1;

function mod(n, m = Q) {
  return ((n % m) + m) % m;
}

function center(v) {
  v = mod(v);
  return v > Q / 2 ? v - Q : v;
}

function uniformMatrix() {
  return Array.from({ length: N }, () =>
    Array.from({ length: N }, () => Math.floor(Math.random() * Q))
  );
}

function smallMatrix() {
  return Array.from({ length: N }, () =>
    Array.from({ length: N }, () =>
      Math.floor(Math.random() * (2 * SMALL_BOUND + 1)) - SMALL_BOUND
    )
  );
}

function matAdd(A, B) {
  return A.map((row, i) => row.map((val, j) => mod(val + B[i][j])));
}

function matSub(A, B) {
  return A.map((row, i) => row.map((val, j) => mod(val - B[i][j])));
}

function matMul(A, B) {
  const result = Array.from({ length: N }, () => new Array(N).fill(0));
  for (let i = 0; i < N; i++) {
    for (let k = 0; k < N; k++) {
      const aik = A[i][k];
      if (aik !== 0) {
        for (let j = 0; j < N; j++) {
          result[i][j] = mod(result[i][j] + aik * B[k][j]);
        }
      }
    }
  }
  return result;
}

function generateKeypair() {
  const A = uniformMatrix();
  const S = smallMatrix();
  const E = smallMatrix();
  const B = matAdd(matMul(A, S), E);
  return { publicKey: { A, B }, privateKey: S };
}

function encapsulate(publicKey) {
  const { A, B } = publicKey;
  const K = Array.from({ length: N }, () =>
    Array.from({ length: N }, () => Math.floor(Math.random() * 2))
  );
  const R1 = smallMatrix();
  const R2 = smallMatrix();
  const E1 = smallMatrix();
  const U = matAdd(matMul(R1, A), E1);
  const V = matAdd(matAdd(matMul(R1, B), R2), K);
  return { ciphertext: { U, V }, K };
}

function decapsulate(privateKey, ciphertext) {
  const { U, V } = ciphertext;
  const M = matSub(V, matMul(U, privateKey));
  const K_rec = Array.from({ length: N }, () => new Array(N).fill(0));
  for (let i = 0; i < N; i++) {
    for (let j = 0; j < N; j++) {
      const v = center(M[i][j]);
      if (Math.abs(v) < Q / 4) K_rec[i][j] = 0;
      else if (Math.abs(v - 1) < Q / 4) K_rec[i][j] = 1;
      else throw new Error('Ошибка декодирования');
    }
  }
  return K_rec;
}

function matrixToBytes(K) {
  return Uint8Array.from(K.flat());
}

// Экспорт для Node.js и для браузера
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { generateKeypair, encapsulate, decapsulate, matrixToBytes };
} else {
  window.NCRLWE = { generateKeypair, encapsulate, decapsulate, matrixToBytes };
}