import crypto from 'node:crypto';
import { getRedis } from '../lib/redis.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const body = req.body || {};
    const recipient = String(body.recipient ?? '').trim();
    const sender = String(body.sender ?? '').trim();
    const payload = body.payload;

    if (!recipient || !sender || !payload || typeof payload !== 'object') {
      return res.status(400).json({ error: 'sender, recipient and payload are required' });
    }

    if (!payload.U || !payload.V || !payload.nonce || !payload.ciphertext) {
      return res.status(400).json({ error: 'Invalid encrypted payload' });
    }

    const redis = getRedis();
    const recipientExists = await redis.exists(`user:${recipient}`);

    if (!recipientExists) {
      return res.status(404).json({ error: 'Получатель не найден' });
    }

    const message = {
      id: crypto.randomUUID(),
      sender,
      recipient,
      createdAt: Date.now(),
      ...payload
    };

    await redis.rpush(`messages:${recipient}`, JSON.stringify(message));

    return res.status(200).json({
      status: 'sent',
      id: message.id
    });
  } catch (error) {
    console.error('POST /api/send:', error);
    return res.status(500).json({ error: error?.message || 'Ошибка отправки' });
  }
}
