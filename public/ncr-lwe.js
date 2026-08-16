// NCR-LWE demo primitive.
// IMPORTANT: this is an educational prototype, NOT production cryptography.
const N = 8;
const Q = 257;
const SMALL_BOUND = 1;
const MESSAGE_ONE = Math.floor(Q / 2);

function mod(n, m = Q) { return ((n % m) + m) % m; }
function center(v) { v = mod(v); return v > Math.floor(Q / 2) ? v - Q : v; }
function randomInt(maxExclusive) {
  if (maxExclusive <= 0) throw new Error('Invalid random range');
  const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  const buf = new Uint32Array(1);
  do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
  return buf[0] % maxExclusive;
}
function uniformMatrix() {
  return Array.from({ length: N }, () => Array.from({ length: N }, () => randomInt(Q)));
}
function smallMatrix() {
  return Array.from({ length: N }, () => Array.from({ length: N }, () => randomInt(2 * SMALL_BOUND + 1) - SMALL_BOUND));
}
function bitMatrix() {
  return Array.from({ length: N }, () => Array.from({ length: N }, () => randomInt(2)));
}
function matAdd(A, B) { return A.map((row, i) => row.map((value, j) => mod(value + B[i][j]))); }
function matSub(A, B) { return A.map((row, i) => row.map((value, j) => mod(value - B[i][j]))); }
function matMul(A, B) {
  const result = Array.from({ length: N }, () => new Array(N).fill(0));
  for (let i = 0; i < N; i++) for (let k = 0; k < N; k++) {
    const aik = A[i][k];
    if (aik === 0) continue;
    for (let j = 0; j < N; j++) result[i][j] = mod(result[i][j] + aik * B[k][j]);
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
  const K = bitMatrix();
  const encodedK = K.map(row => row.map(bit => bit ? MESSAGE_ONE : 0));
  const R1 = smallMatrix();
  const R2 = smallMatrix();
  const E1 = smallMatrix();
  const U = matAdd(matMul(R1, A), E1);
  const V = matAdd(matAdd(matMul(R1, B), R2), encodedK);
  return { ciphertext: { U, V }, K };
}
function decapsulate(privateKey, ciphertext) {
  if (!privateKey || !ciphertext?.U || !ciphertext?.V) throw new Error('Некорректный NCR-LWE ciphertext');
  const M = matSub(ciphertext.V, matMul(ciphertext.U, privateKey));
  const K = Array.from({ length: N }, () => new Array(N).fill(0));
  for (let i = 0; i < N; i++) for (let j = 0; j < N; j++) {
    const residue = mod(M[i][j]);
    const distanceToZero = Math.min(residue, Q - residue);
    const rawDistanceToOne = Math.abs(residue - MESSAGE_ONE);
    const distanceToOne = Math.min(rawDistanceToOne, Q - rawDistanceToOne);
    K[i][j] = distanceToOne < distanceToZero ? 1 : 0;
  }
  return K;
}
function matrixToBytes(K) { return Uint8Array.from(K.flat()); }
window.NCRLWE = { N, Q, generateKeypair, encapsulate, decapsulate, matrixToBytes };