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

    const payloads =
      req.body?.payloads;

    if (!validUsername(recipient)) {
      return res.status(400).json({
        error: 'Некорректный получатель'
      });
    }

    if (
      !Array.isArray(payloads) ||
      !payloads.length
    ) {
      return res.status(400).json({
        error:
          'Необходимо зашифровать сообщение для устройств получателя'
      });
    }

    if (payloads.length > 20) {
      return res.status(400).json({
        error:
          'Слишком много устройств получателя'
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

    const deviceKeys =
      new Map();

    const deviceRecords =
      await redis.keys(
        `device:${recipient}:*`
      );

    for (const key of deviceRecords) {
      const raw =
        await redis.get(key);

      if (!raw) continue;

      try {
        const device =
          typeof raw === 'string'
            ? JSON.parse(raw)
            : raw;

        if (
          device?.deviceId &&
          device?.publicKey
        ) {
          deviceKeys.set(
            device.deviceId,
            device
          );
        }
      } catch {
        // ignore invalid device
      }
    }

    if (!deviceKeys.size) {
      return res.status(404).json({
        error:
          'У получателя нет зарегистрированных устройств'
      });
    }

    const validPayloads = [];

    for (const item of payloads) {
      if (
        !item ||
        typeof item !== 'object'
      ) {
        continue;
      }

      const deviceId =
        String(
          item.deviceId || ''
        );

      const payload =
        item.payload;

      if (
        !deviceId ||
        !deviceKeys.has(deviceId) ||
        !payload ||
        typeof payload !== 'object'
      ) {
        continue;
      }

      if (
        !payload.U ||
        !payload.V ||
        !payload.nonce ||
        !payload.ciphertext
      ) {
        continue;
      }

      const payloadSize =
        JSON.stringify(payload).length;

      if (
        payloadSize > MAX_PAYLOAD_SIZE
      ) {
        continue;
      }

      validPayloads.push({
        deviceId,
        payload
      });
    }

    if (!validPayloads.length) {
      return res.status(400).json({
        error:
          'Нет корректных encrypted payload'
      });
    }

    const messageId =
      crypto.randomUUID();

    const createdAt =
      Date.now();

    let stored = 0;

    /*
     * Для каждого устройства получателя
     * создаём отдельную копию сообщения.
     *
     * У каждого устройства собственный
     * public/private key.
     */
    for (const item of validPayloads) {
      const message = {
        id: messageId,
        deviceId: item.deviceId,
        sender: session.username,
        recipient,
        createdAt,
        ...item.payload
      };

      await redis.rpush(
        `messages:${recipient}:${item.deviceId}`,
        JSON.stringify(message)
      );

      stored++;
    }

    /*
     * Push отправляется на ВСЕ устройства
     * получателя, у которых есть подписка.
     */
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
          {
            type: 'new-message',
            sender: session.username,
            messageId
          }
        );

        pushSent++;
      } catch (pushError) {
        console.error(
          'Push delivery failed:',
          pushError?.statusCode ||
          pushError?.message ||
          pushError
        );

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
      id: messageId,
      stored,
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