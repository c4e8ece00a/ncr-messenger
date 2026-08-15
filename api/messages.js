import { getRedis } from '../lib/redis.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const username = String(req.query?.username ?? '').trim();

  if (!username) {
    return res.status(400).json({ error: 'username query parameter required' });
  }

  try {
    const redis = getRedis();
    const key = `messages:${username}`;

    // MULTI/EXEC makes LRANGE + DEL atomic. A normal pipeline is NOT atomic.
    const result = await redis
      .multi()
      .lrange(key, 0, -1)
      .del(key)
      .exec();

    const rawMessages = Array.isArray(result?.[0]) ? result[0] : [];
    const messages = [];

    for (const raw of rawMessages) {
      try {
        const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (parsed && typeof parsed === 'object') messages.push(parsed);
      } catch (parseError) {
        console.error('Invalid message in Redis:', parseError);
      }
    }

    return res.status(200).json({ messages });
  } catch (error) {
    console.error('GET /api/messages:', error);
    return res.status(500).json({ error: error?.message || 'Ошибка чтения сообщений' });
  }
}
