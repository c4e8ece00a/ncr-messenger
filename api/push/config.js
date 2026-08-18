import { getRedis } from '../../lib/redis.js';

import {
  securityHeaders,
  noStore,
  requireSession
} from '../../lib/security.js';

export default async function handler(req, res) {
  securityHeaders(res);
  noStore(res);

  if (req.method !== 'GET') {
    return res.status(405).json({
      error: 'Method not allowed'
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

    const publicKey =
      process.env.VAPID_PUBLIC_KEY;

    if (!publicKey) {
      return res.status(500).json({
        error: 'Push не настроен'
      });
    }

    return res.status(200).json({
      publicKey
    });
  } catch (error) {
    console.error(
      'GET /api/push/config:',
      error
    );

    return res.status(500).json({
      error: 'Ошибка push-конфигурации'
    });
  }
}
