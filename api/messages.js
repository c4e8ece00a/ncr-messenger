import { getRedis } from '../lib/redis.js';
import { requireSession, noStore, securityHeaders } from '../lib/security.js';

export default async function handler(req, res) {
  securityHeaders(res);
  noStore(res);

  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const redis = getRedis();
    const session = await requireSession(req, res, redis);
    if (!session) return;

    const key = `messages:${session.username}`;

    const result = await redis.multi().lrange(key, 0, -1).del(key).exec();
    const rawMessages = Array.isArray(result?.[0]) ? result[0] : [];
    const messages = [];

    for (const raw of rawMessages) {
      try {
        const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (parsed && typeof parsed === 'object') messages.push(parsed);
      } catch {
        // Do not expose malformed Redis content to clients.
      }
    }

    return res.status(200).json({ messages });
  } catch (error) {
    console.error('GET /api/messages:', error?.message || error);
    return res.status(500).json({ error: 'Ошибка чтения сообщений' });
  }
}