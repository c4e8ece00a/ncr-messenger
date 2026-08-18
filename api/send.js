import crypto from 'node:crypto';

import { getRedis } from '../lib/redis.js';

import {
  noStore,
  securityHeaders,
  requireSession,
  requireSameOrigin,
  jsonBodySize,
  rateLimit,
  normalizeUsername,
  validUsername
} from '../lib/security.js';

import {
  sendPush
} from '../lib/push.js';

const MAX_BODY_SIZE = 128 * 1024;

const MAX_MATRIX_SIZE = 8;

function isValidMatrix(matrix) {
  if (!Array.isArray(matrix)) {
    return false;
  }

  if (matrix.length !== MAX_MATRIX_SIZE) {
    return false;
  }

  return matrix.every(
    row =>
      Array.isArray(row) &&
      row.length === MAX_MATRIX_SIZE &&
      row.every(value => Number.isInteger(value))
  );
}

function validByteArray(value, maxLength) {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.length <= maxLength &&
    value.every(
      value =>
        Number.isInteger(value) &&
        value >= 0 &&
        value <= 255
    )
  );
}

function validatePayload(payload) {
  if (!payload || typeof payload !== 'object') {
    return false;
  }

  if (!isValidMatrix(payload.U)) {
    return false;
  }

  if (!isValidMatrix(payload.V)) {
    return false;
  }

  if (!validByteArray(payload.nonce, 32)) {
    return false;
  }

  if (!validByteArray(payload.ciphertext, 128 * 1024)) {
    return false;
  }

  return true;
}

export default async function handler(req, res) {
  securityHeaders(res);
  noStore(res);

  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  if (!requireSameOrigin(req, res)) {
    return;
  }

  if (jsonBodySize(req) > MAX_BODY_SIZE) {
    return res.status(413).json({
      error: 'Слишком большой запрос'
    });
  }

  try {
    const redis = getRedis();

    const session = await requireSession(req, res, redis);

    if (!session) {
      return;
    }

    const rl = await rateLimit(
      redis,
      `send:${session.username}`,
      60,
      60
    );

    if (!rl.allowed) {
      return res.status(429).json({
        error: 'Слишком много сообщений. Попробуйте позже.'
      });
    }

    const body = req.body || {};

    const recipient = normalizeUsername(body.recipient);
    const payload = body.payload;

    if (!validUsername(recipient)) {
      return res.status(400).json({
        error: 'Некорректный получатель'
      });
    }

    if (!validatePayload(payload)) {
      return res.status(400).json({
        error: 'Некорректный зашифрованный пакет'
      });
    }

    const sender = session.username;

    const recipientExists = await redis.exists(
      `user:${recipient}`
    );

    if (!recipientExists) {
      return res.status(404).json({
        error: 'Получатель не найден'
      });
    }

    const message = {
      id: crypto.randomUUID(),
      sender,
      recipient,
      createdAt: Date.now(),
      U: payload.U,
      V: payload.V,
      nonce: payload.nonce,
      ciphertext: payload.ciphertext
    };

    /*
     * Сначала сохраняем сообщение.
     *
     * Даже если Push-сервис временно недоступен,
     * само сообщение не потеряется.
     */
    await redis.rpush(
      `messages:${recipient}`,
      JSON.stringify(message)
    );

    /*
     * Получаем Push-подписки получателя.
     */
    let pushIds = [];

    try {
      pushIds = await redis.smembers(
        `pushSubs:${recipient}`
      );
    } catch (pushListError) {
      console.error(
        'Unable to read push subscriptions:',
        pushListError
      );
    }

    let pushSent = 0;

    for (const id of pushIds || []) {
      const subscriptionRaw = await redis.get(
        `pushSub:${recipient}:${id}`
      );

      if (!subscriptionRaw) {
        await redis.srem(
          `pushSubs:${recipient}`,
          id
        );

        continue;
      }

      let subscription;

      try {
        subscription =
          typeof subscriptionRaw === 'string'
            ? JSON.parse(subscriptionRaw)
            : subscriptionRaw;
      } catch {
        await redis.del(
          `pushSub:${recipient}:${id}`
        );

        await redis.srem(
          `pushSubs:${recipient}`,
          id
        );

        continue;
      }

      try {
        /*
         * В Push никогда не отправляем текст сообщения.
         */
        await sendPush(subscription, {
          type: 'new-message',
          sender,
          messageId: message.id
        });

        pushSent++;
      } catch (pushError) {
        const statusCode = pushError?.statusCode;

        console.error(
          `Push failed for ${recipient}/${id}:`,
          statusCode || pushError?.message || pushError
        );

        /*
         * 404 / 410 обычно означают,
         * что подписка больше не существует.
         */
        if (statusCode === 404 || statusCode === 410) {
          await redis.del(
            `pushSub:${recipient}:${id}`
          );

          await redis.srem(
            `pushSubs:${recipient}`,
            id
          );
        }
      }
    }

    return res.status(200).json({
      status: 'sent',
      id: message.id,
      pushSent
    });
  } catch (error) {
    console.error(
      'POST /api/send:',
      error?.message || error
    );

    return res.status(500).json({
      error: 'Ошибка отправки'
    });
  }
}
