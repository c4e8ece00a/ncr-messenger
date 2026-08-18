import { getRedis } from '../../lib/redis.js';

import {
  noStore,
  securityHeaders,
  requireSession,
  requireSameOrigin,
  jsonBodySize,
  rateLimit
} from '../../lib/security.js';

import {
  validateSubscription,
  subscriptionId
} from '../../lib/push.js';

const MAX_BODY_SIZE = 16 * 1024;

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

  if (jsonBodySize(req) > MAX_BODY_SIZE) {
    return res.status(413).json({
      error: 'Слишком большой запрос'
    });
  }

  try {
    const redis = getRedis();

    const session = await requireSession(req, res, redis);

    if (!session) {
      return;
    }

    const rl = await rateLimit(
      redis,
      `push-unsubscribe:${session.username}`,
      10,
      300
    );

    if (!rl.allowed) {
      return res.status(429).json({
        error: 'Слишком много запросов'
      });
    }

    const subscription = req.body?.subscription;

    if (!validateSubscription(subscription)) {
      return res.status(400).json({
        error: 'Некорректная Push-подписка'
      });
    }

    const id = subscriptionId(subscription);

    await redis.del(
      `pushSub:${session.username}:${id}`
    );

    await redis.srem(
      `pushSubs:${session.username}`,
      id
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