import {
  hash,
  verify
} from '@node-rs/argon2';

import {
  getRedis
} from '../lib/redis.js';

import {
  MAX_PASSWORD_LENGTH,
  normalizeUsername,
  validUsername,
  newToken,
  newDeviceId,
  sha256,
  setSessionCookie,
  noStore,
  requireSameOrigin,
  rateLimit,
  jsonBodySize,
  securityHeaders
} from '../lib/security.js';

const SESSION_TTL =
  60 * 60 * 24 * 30;

const MIN_PASSWORD_LENGTH = 8;

function genericAuthError(res) {
  return res.status(401).json({
    error:
      'Неверные учетные данные'
  });
}

function validDeviceId(value) {
  return (
    typeof value === 'string' &&
    /^[0-9a-f-]{36}$/i.test(value)
  );
}

function validPublicKey(key) {
  return (
    key &&
    typeof key === 'object' &&
    Array.isArray(key.A) &&
    Array.isArray(key.B)
  );
}

export default async function handler(
  req,
  res
) {
  securityHeaders(res);
  noStore(res);

  if (req.method !== 'POST') {
    return res.status(405).json({
      error:
        'Method not allowed'
    });
  }

  if (
    !requireSameOrigin(
      req,
      res
    )
  ) {
    return;
  }

  if (
    jsonBodySize(req) >
    16 * 1024
  ) {
    return res.status(413).json({
      error:
        'Слишком большой запрос'
    });
  }

  try {
    const body =
      req.body || {};

    const username =
      normalizeUsername(
        body.username
      );

    const password =
      String(
        body.password ?? ''
      );

    const publicKey =
      body.publicKey;

    let deviceId =
      body.deviceId;

    if (
      !validDeviceId(deviceId)
    ) {
      deviceId =
        newDeviceId();
    }

    if (
      !validUsername(username) ||
      password.length <
        MIN_PASSWORD_LENGTH ||
      password.length >
        MAX_PASSWORD_LENGTH
    ) {
      return genericAuthError(res);
    }

    if (
      !validPublicKey(publicKey)
    ) {
      return res.status(400).json({
        error:
          'Некорректный ключ устройства'
      });
    }

    const redis =
      getRedis();

    const ip =
      req.headers[
        'x-forwarded-for'
      ] || 'unknown';

    const rl =
      await rateLimit(
        redis,
        `login:${username}:${ip}`,
        5,
        300
      );

    if (!rl.allowed) {
      return res.status(429).json({
        error:
          'Слишком много попыток. Попробуйте позже.'
      });
    }

    const userKey =
      `user:${username}`;

    const existing =
      await redis.get(
        userKey
      );

    if (!existing) {
      const passwordHash =
        await hash(
          password,
          {
            algorithm:
              'argon2id',
            memoryCost:
              19456,
            timeCost: 2,
            parallelism: 1
          }
        );

      await redis.set(
        userKey,
        JSON.stringify({
          username,
          passwordHash,
          createdAt:
            Date.now()
        })
      );
    } else {
      const user =
        typeof existing === 'string'
          ? JSON.parse(existing)
          : existing;

      let valid = false;

      if (
        user?.passwordHash
      ) {
        valid =
          await verify(
            user.passwordHash,
            password
          );
      }

      if (
        !valid &&
        user?.passwordHash?.startsWith(
          'sha256:'
        )
      ) {
        const legacy =
          sha256(password);

        if (
          legacy ===
          user.passwordHash.slice(7)
        ) {
          const upgraded =
            await hash(
              password,
              {
                algorithm:
                  'argon2id',
                memoryCost:
                  19456,
                timeCost: 2,
                parallelism: 1
              }
            );

          user.passwordHash =
            upgraded;

          await redis.set(
            userKey,
            JSON.stringify(user)
          );

          valid = true;
        }
      }

      if (!valid) {
        return genericAuthError(
          res
        );
      }
    }

    /*
     * Регистрируем public key
     * конкретного устройства.
     */
    await redis.set(
      `device:${username}:${deviceId}`,
      JSON.stringify({
        username,
        deviceId,
        publicKey,
        createdAt:
          Date.now(),
        updatedAt:
          Date.now()
      })
    );

    const token =
      newToken(32);

    await redis.set(
      `session:${sha256(token)}`,
      JSON.stringify({
        username,
        deviceId,
        createdAt:
          Date.now()
      }),
      {
        ex: SESSION_TTL
      }
    );

    setSessionCookie(
      res,
      token,
      SESSION_TTL
    );

    return res.status(200).json({
      status: 'ok',
      username,
      deviceId
    });
  } catch (error) {
    console.error(
      'POST /api/auth:',
      error?.message ||
        error
    );

    return res.status(500).json({
      error:
        'Ошибка авторизации'
    });
  }
}