/*
 * NCR-LWE DEMO
 *
 * ВАЖНО:
 * Это демонстрационная реализация.
 * Не использовать для реальной криптографической защиты.
 */

const N = 8;
const Q = 257;
const SMALL_BOUND = 1;

function mod(n, m = Q) {
  return ((n % m) + m) % m;
}

function center(v) {
  v = mod(v);

  return v > Q / 2
    ? v - Q
    : v;
}

function uniformMatrix() {
  return Array.from(
    { length: N },
    () =>
      Array.from(
        { length: N },
        () => Math.floor(Math.random() * Q)
      )
  );
}

function smallMatrix() {
  return Array.from(
    { length: N },
    () =>
      Array.from(
        { length: N },
        () =>
          Math.floor(
            Math.random() * (2 * SMALL_BOUND + 1)
          ) - SMALL_BOUND
      )
  );
}

function matAdd(A, B) {
  return A.map((row, i) =>
    row.map((value, j) =>
      mod(value + B[i][j])
    )
  );
}

function matSub(A, B) {
  return A.map((row, i) =>
    row.map((value, j) =>
      mod(value - B[i][j])
    )
  );
}

function matMul(A, B) {
  const result = Array.from(
    { length: N },
    () => new Array(N).fill(0)
  );

  for (let i = 0; i < N; i++) {
    for (let k = 0; k < N; k++) {
      const aik = A[i][k];

      if (aik === 0) {
        continue;
      }

      for (let j = 0; j < N; j++) {
        result[i][j] = mod(
          result[i][j] +
          aik * B[k][j]
        );
      }
    }
  }

  return result;
}

function validateMatrix(matrix, name) {
  if (!Array.isArray(matrix)) {
    throw new Error(
      `${name}: матрица отсутствует`
    );
  }

  if (matrix.length !== N) {
    throw new Error(
      `${name}: неверный размер`
    );
  }

  for (const row of matrix) {
    if (
      !Array.isArray(row) ||
      row.length !== N
    ) {
      throw new Error(
        `${name}: неверная структура`
      );
    }
  }
}

function generateKeypair() {
  const A = uniformMatrix();

  const S = smallMatrix();
  const E = smallMatrix();

  const B = matAdd(
    matMul(A, S),
    E
  );

  return {
    publicKey: {
      A,
      B
    },
    privateKey: S
  };
}

function encapsulate(publicKey) {
  validateMatrix(publicKey.A, 'A');
  validateMatrix(publicKey.B, 'B');

  const {
    A,
    B
  } = publicKey;

  /*
   * Сессионный ключ.
   */
  const K = Array.from(
    { length: N },
    () =>
      Array.from(
        { length: N },
        () => Math.floor(Math.random() * 2)
      )
  );

  const R1 = smallMatrix();
  const R2 = smallMatrix();
  const E1 = smallMatrix();

  const U = matAdd(
    matMul(R1, A),
    E1
  );

  const V = matAdd(
    matAdd(
      matMul(R1, B),
      R2
    ),
    K
  );

  return {
    ciphertext: {
      U,
      V
    },
    K
  };
}

function decapsulate(privateKey, ciphertext) {
  validateMatrix(
    privateKey,
    'privateKey'
  );

  if (!ciphertext) {
    throw new Error(
      'Отсутствует ciphertext'
    );
  }

  validateMatrix(
    ciphertext.U,
    'U'
  );

  validateMatrix(
    ciphertext.V,
    'V'
  );

  const {
    U,
    V
  } = ciphertext;

  const M = matSub(
    V,
    matMul(U, privateKey)
  );

  const K_rec = Array.from(
    { length: N },
    () => new Array(N).fill(0)
  );

  for (let i = 0; i < N; i++) {
    for (let j = 0; j < N; j++) {

      const value = center(
        M[i][j]
      );

      /*
       * Вместо старой схемы:
       *
       * if (...) 0
       * else if (...) 1
       * else throw
       *
       * выбираем ближайший допустимый символ.
       *
       * Для данной демонстрационной схемы
       * допустимы 0 и 1.
       */

      const distanceToZero =
        Math.abs(value);

      const distanceToOne =
        Math.min(
          Math.abs(value - 1),
          Math.abs(value + Q - 1),
          Math.abs(value - Q - 1)
        );

      K_rec[i][j] =
        distanceToZero <= distanceToOne
          ? 0
          : 1;
    }
  }

  return K_rec;
}

function matrixToBytes(K) {
  validateMatrix(K, 'K');

  return Uint8Array.from(
    K.flat().map(value => value & 1)
  );
}

window.NCRLWE = {
  generateKeypair,
  encapsulate,
  decapsulate,
  matrixToBytes
};
