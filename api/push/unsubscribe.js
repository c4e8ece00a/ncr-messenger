import { getRedis } from '../../lib/redis.js';
import {
  securityHeaders,
  noStore,
  requireSession,
  requireSameOrigin,
  jsonBodySize
} from '../../lib/security.js';

export default async function handler(req, res) {
  securityHeaders(res);
  noStore(res);

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!requireSameOrigin(req, res)) return;

  if (jsonBodySize(req) > 8 * 1024) {
    return res.status(413).json({ error: 'Слишком большой запрос' });
  }

  try {
    const redis = getRedis();
    const session = await requireSession(req, res, redis);
    if (!session) return;

    await redis.del(`push:${session.username}:${session.deviceId}`);
    await redis.srem(`pushDevices:${session.username}`, session.deviceId);

    return res.status(200).json({ status: 'unsubscribed' });
  } catch (error) {
    console.error('POST /api/push/unsubscribe:', error?.message || error);
    return res.status(500).json({ error: 'Ошибка отключения уведомлений' });
  }
}
