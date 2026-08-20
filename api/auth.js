import crypto from 'node:crypto';
import { hash, verify } from '@node-rs/argon2';

import { getRedis } from '../lib/redis.js';

import {
  MAX_PASSWORD_LENGTH,
  normalizeUsername,
  validUsername,
  newToken,
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

const MIN_PASSWORD_LENGTH =
  8;


/*
 * Создаём уникальный идентификатор
 * конкретного устройства.
 *
 * Он НЕ является секретом.
 * Он нужен для привязки Push-подписки
 * к конкретному устройству.
 */
function createDeviceId() {
  return crypto.randomUUID();
}


function genericAuthError(res) {
  return res.status(401).json({
    error:
      'Неверные учетные данные'
  });
}


async function createPasswordHash(password) {
  return hash(
    password,
    {
      algorithm: 'argon2id',

      memoryCost: 19456,

      timeCost: 2,

      parallelism: 1
    }
  );
}


export default async function handler(req, res) {
  securityHeaders(res);
  noStore(res);


  if (req.method !== 'POST') {
    return res.status(405).json({
      error:
        'Method not allowed'
    });
  }


  if (!requireSameOrigin(req, res)) {
    return;
  }


  if (jsonBodySize(req) > 16 * 1024) {
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


    /*
     * Проверяем входные данные.
     */
    if (
      !validUsername(username) ||
      password.length <
        MIN_PASSWORD_LENGTH ||
      password.length >
        MAX_PASSWORD_LENGTH
    ) {
      return genericAuthError(res);
    }


    const redis =
      getRedis();


    /*
     * Ограничение количества
     * попыток авторизации.
     */
    const ip =
      req.headers[
        'x-forwarded-for'
      ] ||
      'unknown';


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


    /*
     * =========================================
     * НОВЫЙ ПОЛЬЗОВАТЕЛЬ
     * =========================================
     */
    if (!existing) {

      if (
        !publicKey ||
        typeof publicKey !==
          'object'
      ) {
        return res.status(400).json({
          error:
            'Для нового аккаунта требуется publicKey'
        });
      }


      const passwordHash =
        await createPasswordHash(
          password
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


      /*
       * Публичный ключ шифрования
       * пользователя сохраняется
       * отдельно от его пароля.
       */
      await redis.set(
        `publicKey:${username}`,

        publicKey
      );

    } else {

      /*
       * =========================================
       * СУЩЕСТВУЮЩИЙ ПОЛЬЗОВАТЕЛЬ
       * =========================================
       */

      let user;


      try {
        user =
          typeof existing ===
            'string'
            ? JSON.parse(existing)
            : existing;

      } catch {
        return genericAuthError(res);
      }


      let valid =
        false;


      /*
       * Основной вариант —
       * Argon2id.
       */
      if (
        user?.passwordHash
      ) {
        try {
          valid =
            await verify(
              user.passwordHash,
              password
            );

        } catch (verifyError) {
          /*
           * Если старый hash имеет
           * неподдерживаемый формат,
           * ниже попробуем legacy SHA-256.
           */
          console.error(
            'Password verification:',
            verifyError?.message ||
            verifyError
          );

          valid = false;
        }
      }


      /*
       * =========================================
       * LEGACY SHA-256 MIGRATION
       * =========================================
       *
       * Старые аккаунты могут иметь:
       *
       * sha256:<hash>
       *
       * При успешном входе сразу
       * переводим пароль на Argon2id.
       */
      if (
        !valid &&
        typeof user?.passwordHash ===
          'string' &&
        user.passwordHash.startsWith(
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
            await createPasswordHash(
              password
            );


          user.passwordHash =
            upgraded;


          await redis.set(
            userKey,

            JSON.stringify(
              user
            )
          );


          valid = true;
        }
      }


      if (!valid) {
        return genericAuthError(res);
      }


      /*
       * Не заменяем существующий
       * публичный ключ пользователя.
       *
       * Это важно для E2E-шифрования.
       */
      if (publicKey) {

        const storedKey =
          await redis.get(
            `publicKey:${username}`
          );


        if (!storedKey) {

          await redis.set(
            `publicKey:${username}`,

            publicKey
          );
        }
      }
    }


    /*
     * =========================================
     * DEVICE ID
     * =========================================
     *
     * Каждый успешный вход получает
     * собственный deviceId.
     *
     * Поэтому один аккаунт может иметь:
     *
     * iPhone  -> device A
     * iPad    -> device B
     * Browser -> device C
     *
     * Каждая Push-подписка будет
     * привязана к своему устройству.
     */
    const deviceId =
      createDeviceId();


    /*
     * =========================================
     * SESSION
     * =========================================
     */

    const token =
      newToken(32);


    const tokenHash =
      sha256(token);


    const session = {
      username,

      deviceId,

      createdAt:
        Date.now()
    };


    await redis.set(
      `session:${tokenHash}`,

      JSON.stringify(
        session
      ),

      {
        ex:
          SESSION_TTL
      }
    );


    setSessionCookie(
      res,

      token,

      SESSION_TTL
    );


    /*
     * Клиенту deviceId обычно
     * не нужно возвращать.
     *
     * Он уже находится
     * внутри серверной сессии.
     */
    return res.status(200).json({
      status:
        'ok',

      username
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