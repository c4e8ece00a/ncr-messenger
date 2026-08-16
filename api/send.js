import crypto from 'node:crypto';
import { getRedis } from '../lib/redis.js';
import {
  normalizeUsername, validUsername, requireSession, noStore, securityHeaders,
  requireSameOrigin, rateLimit, jsonBodySize, MAX_MESSAGE_BYTES
} from '../lib/security.js';

function validEncryptedPayload(payload) {
  if (!payload || typeof payload !== 'object') return false;
  if (!Array.isArray(payload.U) || !Array.isArray(payload.V)) return false;
  if (!Array.isArray(payload.nonce) || payload.nonce.length !== 12) return false;
  if (!Array.isArray(payload.ciphertext) || payload.ciphertext.length < 16) return false;
  if (JSON.stringify(payload).length > MAX_MESSAGE_BYTES) return false;
  return true;
}

export default async function handler(req, res) {
  securityHeaders(res);
  noStore(res);

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (!requireSameOrigin(req, res)) return;
  if (jsonBodySize(req) > MAX_MESSAGE_BYTES) return res.status(413).json({ error: 'Сообщение слишком большое' });

  try {
    const redis = getRedis();
    const session = await requireSession(req, res, redis);
    if (!session) return;

    const rl = await rateLimit(redis, `send:${session.username}`, 30, 60);
    if (!rl.allowed) return res.status(429).json({ error: 'Слишком много сообщений' });

    const body = req.body || {};
    const recipient = normalizeUsername(body.recipient);
    const payload = body.payload;

    if (!validUsername(recipient) || !validEncryptedPayload(payload)) {
      return res.status(400).json({ error: 'Некорректное сообщение' });
    }
    if (recipient === session.username) {
      return res.status(400).json({ error: 'Нельзя отправить сообщение самому себе' });
    }

    const recipientExists = await redis.exists(`user:${recipient}`);
    if (!recipientExists) return res.status(404).json({ error: 'Получатель не найден' });

    const message = {
      id: crypto.randomUUID(),
      sender: session.username,
      recipient,
      createdAt: Date.now(),
      ...payload
    };

    await redis.rpush(`messages:${recipient}`, JSON.stringify(message));

    return res.status(200).json({ status: 'sent', id: message.id });
  } catch (error) {
    console.error('POST /api/send:', error?.message || error);
    return res.status(500).json({ error: 'Ошибка отправки' });
  }
}