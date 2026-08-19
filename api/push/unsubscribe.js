import crypto from 'node:crypto';

import {
  getRedis
} from '../../lib/redis.js';

import {
  securityHeaders,
  noStore,
  requireSession,
  requireSameOrigin,
  jsonBodySize
} from '../../lib/security.js';

export default async function handler(
  req,
  res
) {
  securityHeaders(res);
  noStore(res);

  if (req.method !== 'POST') {
    return res.status(405).json({
      error:
        'Method not allowed'
    });
  }

  if (
    !requireSameOrigin(
      req,
      res
    )
  ) {
    return;
  }

  if (
    jsonBodySize(req) >
    8 * 1024
  ) {
    return res.status(413).json({
      error:
        'Слишком большой запрос'
    });
  }

  try {
    const redis =
      getRedis();

    const session =
      await requireSession(
        req,
        res,
        redis
      );

    if (!session) return;

    const endpoint =
      String(
        req.body?.endpoint ||
          ''
      );

    if (!endpoint) {
      return res.status(400).json({
        error:
          'Endpoint не указан'
      });
    }

    const endpointHash =
      crypto
        .createHash('sha256')
        .update(endpoint)
        .digest('hex');

    const key =
      `push:${session.username}:${endpointHash}`;

    const raw =
      await redis.get(key);

    if (raw) {
      let stored;

      try {
        stored =
          typeof raw === 'string'
            ? JSON.parse(raw)
            : raw;
      } catch {
        stored = null;
      }

      if (
        stored?.username ===
          session.username &&
        stored?.deviceId ===
          session.deviceId
      ) {
        await redis.del(key);
      }
    }

    return res.status(200).json({
      status:
        'unsubscribed'
    });
  } catch (error) {
    console.error(
      'POST /api/push/unsubscribe:',
      error?.message ||
        error
    );

    return res.status(500).json({
      error:
        'Ошибка отключения уведомлений'
    });
  }
}