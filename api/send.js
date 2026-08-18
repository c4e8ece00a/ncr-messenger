import crypto from 'node:crypto';

import { getRedis } from '../lib/redis.js';
import { sendPush } from '../lib/push.js';

import {
  securityHeaders,
  noStore,
  requireSession,
  requireSameOrigin,
  jsonBodySize,
  normalizeUsername,
  validUsername
} from '../lib/security.js';

const MAX_PAYLOAD_SIZE = 60000;

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

  if (jsonBodySize(req) > 64 * 1024) {
    return res.status(413).json({
      error: 'Сообщение слишком большое'
    });
  }

  try {
    const redis = getRedis();

    const session =
      await requireSession(
        req,
        res,
        redis
      );

    if (!session) return;

    const recipient =
      normalizeUsername(
        req.body?.recipient
      );

    const payload =
      req.body?.payload;

    if (!validUsername(recipient)) {
      return res.status(400).json({
        error: 'Некорректный получатель'
      });
    }

    if (
      !payload ||
      typeof payload !== 'object'
    ) {
      return res.status(400).json({
        error: 'Некорректный encrypted payload'
      });
    }

    if (
      !payload.U ||
      !payload.V ||
      !payload.nonce ||
      !payload.ciphertext
    ) {
      return res.status(400).json({
        error: 'Повреждённый encrypted payload'
      });
    }

    const payloadSize =
      JSON.stringify(payload).length;

    if (payloadSize > MAX_PAYLOAD_SIZE) {
      return res.status(413).json({
        error: 'Encrypted payload слишком большой'
      });
    }

    const recipientExists =
      await redis.exists(
        `user:${recipient}`
      );

    if (!recipientExists) {
      return res.status(404).json({
        error: 'Получатель не найден'
      });
    }

    const message = {
      id: crypto.randomUUID(),

      sender: session.username,

      recipient,

      createdAt: Date.now(),

      ...payload
    };

    await redis.rpush(
      `messages:${recipient}`,
      JSON.stringify(message)
    );

    /*
     * Push содержит только информацию о событии.
     *
     * Никакого текста сообщения здесь нет.
     */
    const pushPayload = {
      type: 'new-message',
      sender: session.username,
      messageId: message.id
    };

    const subscriptions =
      await redis.keys(
        `push:${recipient}:*`
      );

    let pushSent = 0;

    for (const key of subscriptions) {
      try {
        const raw =
          await redis.get(key);

        if (!raw) continue;

        const subscription =
          typeof raw === 'string'
            ? JSON.parse(raw)
            : raw;

        await sendPush(
          subscription,
          pushPayload
        );

        pushSent++;
      } catch (pushError) {
        console.error(
          'Push delivery failed:',
          pushError?.statusCode ||
          pushError?.message ||
          pushError
        );

        /*
         * 404/410 означает,
         * что подписка больше не существует.
         */
        if (
          pushError?.statusCode === 404 ||
          pushError?.statusCode === 410
        ) {
          await redis.del(key);
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
