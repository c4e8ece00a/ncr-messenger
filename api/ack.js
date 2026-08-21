import { getRedis } from '../lib/redis.js';
import {
  noStore,
  securityHeaders,
  requireSession,
  requireSameOrigin,
  jsonBodySize
} from '../lib/security.js';

const MAX_ACK_BODY = 4096;

export default async function handler(req, res) {
  securityHeaders(res);
  noStore(res);

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!requireSameOrigin(req, res)) return;

  if (jsonBodySize(req) > MAX_ACK_BODY) {
    return res.status(413).json({ error: 'Слишком большой запрос' });
  }

  try {
    const redis = getRedis();
    const session = await requireSession(req, res, redis);
    if (!session) return;

    const messageId = String(req.body?.messageId || '').trim();

    if (!messageId || messageId.length > 128) {
      return res.status(400).json({ error: 'Некорректный messageId' });
    }

    const key = `messages:${session.username}:${session.deviceId}`;
    const rawMessages = await redis.lrange(key, 0, -1);
    let targetRaw = null;

    for (const raw of rawMessages) {
      try {
        const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (parsed?.id === messageId && parsed?.recipient === session.username) {
          targetRaw = typeof raw === 'string' ? raw : JSON.stringify(raw);
          break;
        }
      } catch {
        // Ignore malformed queue entries.
      }
    }

    if (!targetRaw) {
      return res.status(200).json({ status: 'already-acked' });
    }

    const removed = await redis.lrem(key, 1, targetRaw);

    return res.status(200).json(
      removed > 0
        ? { status: 'acked', messageId }
        : { status: 'already-acked' }
    );
  } catch (error) {
    console.error('POST /api/ack:', error?.message || error);
    return res.status(500).json({ error: 'Ошибка подтверждения сообщения' });
  }
}