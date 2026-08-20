import { getRedis } from '../lib/redis.js';

import {
  securityHeaders,
  noStore,
  requireSession,
  normalizeUsername,
  validUsername
} from '../lib/security.js';

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

    const session = await requireSession(req, res, redis);
    if (!session) return;

    const username = normalizeUsername(req.query?.username);

    if (!validUsername(username)) {
      return res.status(400).json({
        error: 'Некорректное имя пользователя'
      });
    }

    const publicKey = await redis.get(`publicKey:${username}`);

    if (!publicKey) {
      return res.status(404).json({
        error: 'Пользователь не найден'
      });
    }

    return res.status(200).json({ publicKey });
  } catch (error) {
    console.error(
      'GET /api/publicKey:',
      error?.message || error
    );

    return res.status(500).json({
      error: 'Ошибка базы данных'
    });
  }
}
