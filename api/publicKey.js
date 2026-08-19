import {
  getRedis
} from '../lib/redis.js';

import {
  securityHeaders,
  noStore,
  requireSession,
  normalizeUsername,
  validUsername
} from '../lib/security.js';

export default async function handler(
  req,
  res
) {
  securityHeaders(res);
  noStore(res);

  if (req.method !== 'GET') {
    return res.status(405).json({
      error:
        'Method not allowed'
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

    const username =
      normalizeUsername(
        req.query?.username
      );

    if (
      !validUsername(username)
    ) {
      return res.status(400).json({
        error:
          'Некорректное имя пользователя'
      });
    }

    const keys =
      await redis.keys(
        `device:${username}:*`
      );

    const devices = [];

    for (
      const key of keys
    ) {
      const raw =
        await redis.get(key);

      if (!raw) continue;

      try {
        const device =
          typeof raw === 'string'
            ? JSON.parse(raw)
            : raw;

        if (
          device?.deviceId &&
          device?.publicKey
        ) {
          devices.push({
            deviceId:
              device.deviceId,

            publicKey:
              device.publicKey
          });
        }
      } catch {}
    }

    if (
      devices.length === 0
    ) {
      return res.status(404).json({
        error:
          'У пользователя нет зарегистрированных устройств'
      });
    }

    return res.status(200).json({
      devices
    });
  } catch (error) {
    console.error(
      'GET /api/publicKey:',
      error?.message ||
        error
    );

    return res.status(500).json({
      error:
        'Ошибка базы данных'
    });
  }
}