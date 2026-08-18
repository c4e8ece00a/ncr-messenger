import crypto from 'node:crypto';

import { getRedis } from '../../lib/redis.js';

import {
  securityHeaders,
  noStore,
  requireSession,
  requireSameOrigin
} from '../../lib/security.js';

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

  try {
    const redis = getRedis();

    const session =
      await requireSession(
        req,
        res,
        redis
      );

    if (!session) return;

    const endpoint =
      String(
        req.body?.endpoint || ''
      );

    if (!endpoint) {
      return res.status(400).json({
        error: 'endpoint required'
      });
    }

    const hash =
      crypto
        .createHash('sha256')
        .update(endpoint)
        .digest('hex');

    await redis.del(
      `push:${session.username}:${hash}`
    );

    return res.status(200).json({
      status: 'unsubscribed'
    });
  } catch (error) {
    console.error(
      'POST /api/push/unsubscribe:',
      error?.message || error
    );

    return res.status(500).json({
      error: 'Ошибка отключения уведомлений'
    });
  }
}
