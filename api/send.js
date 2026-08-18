import crypto from 'node:crypto';

import { getRedis } from '../lib/redis.js';

import {
  MAX_MESSAGE_BYTES,
  noStore,
  securityHeaders,
  requireSession,
  requireSameOrigin,
  jsonBodySize,
  normalizeUsername,
  validUsername,
  rateLimit,
  isValidCiphertext,
  isValidByteArray
} from '../lib/security.js';

const MAX_CIPHERTEXT_BYTES = 32768;
const MAX_PAYLOAD_JSON_BYTES = 65536;

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

  const bodySize = jsonBodySize(req);

  if (
    bodySize > MAX_PAYLOAD_JSON_BYTES
  ) {
    return res.status(413).json({
      error: 'Слишком большой запрос'
    });
  }

  try {
    const redis = getRedis();

    const session = await requireSession(
      req,
      res,
      redis
    );

    if (!session) {
      return;
    }

    const sender = normalizeUsername(
      session.username
    );

    const body = req.body || {};

    const recipient = normalizeUsername(
      body.recipient
    );

    const payload = body.payload;

    if (!validUsername(sender)) {
      return res.status(401).json({
        error: 'Недействительная сессия'
      });
    }

    if (!validUsername(recipient)) {
      return res.status(400).json({
        error: 'Некорректное имя получателя'
      });
    }

    if (sender === recipient) {
      return res.status(400).json({
        error: 'Нельзя отправить сообщение самому себе'
      });
    }

    if (
      !payload ||
      typeof payload !== 'object' ||
      Array.isArray(payload)
    ) {
      return res.status(400).json({
        error: 'Некорректный зашифрованный пакет'
      });
    }

    if (
      !isValidCiphertext({
        U: payload.U,
        V: payload.V
      })
    ) {
      return res.status(400).json({
        error: 'Некорректный NCR-LWE ciphertext'
      });
    }

    if (
      !isValidByteArray(payload.nonce, 12)
    ) {
      return res.status(400).json({
        error: 'Некорректный nonce'
      });
    }

    if (
      !isValidByteArray(payload.ciphertext) ||
      payload.ciphertext.length < 16 ||
      payload.ciphertext.length > MAX_CIPHERTEXT_BYTES
    ) {
      return res.status(400).json({
        error: 'Некорректный ciphertext'
      });
    }

    const serializedPayload =
      JSON.stringify(payload);

    if (
      Buffer.byteLength(
        serializedPayload,
        'utf8'
      ) > MAX_MESSAGE_BYTES
    ) {
      return res.status(413).json({
        error: 'Сообщение слишком большое'
      });
    }

    const rl = await rateLimit(
      redis,
      `send:${sender}`,
      30,
      60
    );

    if (!rl.allowed) {
      return res.status(429).json({
        error: 'Слишком много сообщений. Попробуйте позже.'
      });
    }

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

    await redis.rpush(
      `messages:${recipient}`,
      JSON.stringify(message)
    );

    return res.status(200).json({
      status: 'sent',
      id: message.id
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