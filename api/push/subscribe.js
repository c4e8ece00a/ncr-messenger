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
    16 * 1024
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

    const subscription =
      req.body?.subscription;

    if (
      !subscription ||
      typeof subscription !==
        'object'
    ) {
      return res.status(400).json({
        error:
          'Некорректная push-подписка'
      });
    }

    if (
      typeof subscription.endpoint !==
        'string' ||
      !subscription.endpoint
    ) {
      return res.status(400).json({
        error:
          'Некорректный endpoint'
      });
    }

    if (
      !subscription.keys ||
      typeof subscription.keys !==
        'object' ||
      typeof subscription.keys.p256dh !==
        'string' ||
      typeof subscription.keys.auth !==
        'string'
    ) {
      return res.status(400).json({
        error:
          'Некорректные ключи push-подписки'
      });
    }

    /*
     * Проверяем, что устройство
     * действительно зарегистрировано
     * у текущего аккаунта.
     */
    const deviceKey =
      `device:${session.username}:${session.deviceId}`;

    const deviceRaw =
      await redis.get(
        deviceKey
      );

    if (!deviceRaw) {
      return res.status(400).json({
        error:
          'Устройство не зарегистрировано'
      });
    }

    const endpointHash =
      crypto
        .createHash('sha256')
        .update(
          subscription.endpoint
        )
        .digest('hex');

    const key =
      `push:${session.username}:${endpointHash}`;

    await redis.set(
      key,
      JSON.stringify({
        username:
          session.username,

        deviceId:
          session.deviceId,

        subscription,

        updatedAt:
          Date.now()
      })
    );

    return res.status(200).json({
      status:
        'subscribed'
    });
  } catch (error) {
    console.error(
      'POST /api/push/subscribe:',
      error?.message ||
        error
    );

    return res.status(500).json({
      error:
        'Ошибка регистрации уведомлений'
    });
  }
}