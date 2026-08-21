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
  validUsername,
  validDeviceId
} from '../lib/security.js';

const MAX_PAYLOAD_SIZE = 60000;
const MAX_ENVELOPES = 32;

function isMatrix(value) {
  return Array.isArray(value) && value.length === 8 && value.every(
    row => Array.isArray(row) && row.length === 8 && row.every(
      cell => Number.isInteger(cell) && cell >= 0 && cell <= 256
    )
  );
}

function isBytes(value, minLength, maxLength) {
  return Array.isArray(value) &&
    value.length >= minLength &&
    value.length <= maxLength &&
    value.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255);
}

function validEnvelope(envelope) {
  return Boolean(
    envelope &&
    typeof envelope === 'object' &&
    validDeviceId(envelope.deviceId) &&
    isMatrix(envelope.U) &&
    isMatrix(envelope.V) &&
    isBytes(envelope.nonce, 12, 12) &&
    isBytes(envelope.ciphertext, 1, 50000)
  );
}

async function getRecipientDeviceIds(redis, username) {
  const ids = await redis.smembers(`devices:${username}`);
  return (ids || []).filter(validDeviceId);
}

export default async function handler(req, res) {
  securityHeaders(res);
  noStore(res);

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!requireSameOrigin(req, res)) return;

  if (jsonBodySize(req) > 64 * 1024) {
    return res.status(413).json({ error: 'Сообщение слишком большое' });
  }

  try {
    const redis = getRedis();
    const session = await requireSession(req, res, redis);
    if (!session) return;

    const recipient = normalizeUsername(req.body?.recipient);
    const payload = req.body?.payload;

    if (!validUsername(recipient)) {
      return res.status(400).json({ error: 'Некорректный получатель' });
    }

    if (!payload || typeof payload !== 'object') {
      return res.status(400).json({ error: 'Некорректный encrypted payload' });
    }

    let envelopes = Array.isArray(payload.envelopes)
      ? payload.envelopes
      : [];

    /* Temporary compatibility: accept one legacy envelope and deliver it only to the
       current recipient device when it is explicitly addressed with a deviceId. */
    if (envelopes.length === 0 && payload.deviceId) {
      envelopes = [{
        deviceId: payload.deviceId,
        U: payload.U,
        V: payload.V,
        nonce: payload.nonce,
        ciphertext: payload.ciphertext
      }];
    }

    if (envelopes.length === 0 || envelopes.length > MAX_ENVELOPES) {
      return res.status(400).json({ error: 'Некорректные encrypted envelopes' });
    }

    const payloadSize = JSON.stringify(payload).length;
    if (payloadSize > MAX_PAYLOAD_SIZE) {
      return res.status(413).json({ error: 'Encrypted payload слишком большой' });
    }

    const recipientExists = await redis.exists(`user:${recipient}`);
    if (!recipientExists) {
      return res.status(404).json({ error: 'Получатель не найден' });
    }

    const recipientDeviceIds = await getRecipientDeviceIds(redis, recipient);
    const allowed = new Set(recipientDeviceIds);

    /* Legacy accounts may still have only publicKey:<username>. They must migrate by
       logging in on a device before multi-device delivery can be used. */
    if (recipientDeviceIds.length === 0) {
      return res.status(409).json({
        error: 'У получателя нет зарегистрированных устройств'
      });
    }

    const seen = new Set();
    const accepted = [];

    for (const envelope of envelopes) {
      if (!validEnvelope(envelope)) {
        return res.status(400).json({ error: 'Повреждённый encrypted envelope' });
      }

      if (seen.has(envelope.deviceId)) continue;
      seen.add(envelope.deviceId);

      if (!allowed.has(envelope.deviceId)) {
        return res.status(400).json({ error: 'Envelope адресован неизвестному устройству' });
      }

      const deviceRecord = await redis.get(
        `device:${recipient}:${envelope.deviceId}`
      );

      if (!deviceRecord) {
        return res.status(409).json({ error: 'Устройство получателя больше не зарегистрировано' });
      }

      accepted.push(envelope);
    }

    if (accepted.length === 0) {
      return res.status(400).json({ error: 'Нет корректных устройств получателя' });
    }

    const messageId = crypto.randomUUID();
    const createdAt = Date.now();
    const pushPayload = {
      type: 'new-message',
      sender: session.username,
      messageId,
      url: '/'
    };

    let pushSent = 0;
    let stored = 0;

    for (const envelope of accepted) {
      const message = {
        id: messageId,
        sender: session.username,
        recipient,
        deviceId: envelope.deviceId,
        createdAt,
        U: envelope.U,
        V: envelope.V,
        nonce: envelope.nonce,
        ciphertext: envelope.ciphertext
      };

      await redis.rpush(
        `messages:${recipient}:${envelope.deviceId}`,
        JSON.stringify(message)
      );
      stored++;
    }

    /* Push is best-effort and never controls message delivery. */
    const pushKeys = await redis.smembers(`pushDevices:${recipient}`);

    for (const deviceId of pushKeys || []) {
      if (!validDeviceId(deviceId)) continue;

      const raw = await redis.get(`push:${recipient}:${deviceId}`);
      if (!raw) {
        await redis.srem(`pushDevices:${recipient}`, deviceId);
        continue;
      }

      try {
        const record = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (!record?.subscription) continue;

        await sendPush(record.subscription, pushPayload);
        pushSent++;
      } catch (pushError) {
        console.error(
          'Push delivery failed:',
          pushError?.statusCode || pushError?.message || pushError
        );

        if (pushError?.statusCode === 404 || pushError?.statusCode === 410) {
          await redis.del(`push:${recipient}:${deviceId}`);
          await redis.srem(`pushDevices:${recipient}`, deviceId);
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
    console.error('POST /api/send:', error?.message || error);
    return res.status(500).json({ error: 'Ошибка отправки' });
  }
}
