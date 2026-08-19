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

const MAX_HISTORY = 200;

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
      !validUsername(username) ||
      username !==
        session.username
    ) {
      return res.status(403).json({
        error:
          'Недопустимый пользователь'
      });
    }

    const rawMessages =
      await redis.lrange(
        `messages:${username}`,
        -MAX_HISTORY,
        -1
      );

    const messages = [];

    for (
      const raw of rawMessages
    ) {
      try {
        const parsed =
          typeof raw === 'string'
            ? JSON.parse(raw)
            : raw;

        if (
          !parsed ||
          typeof parsed !==
            'object'
        ) {
          continue;
        }

        /*
         * Новая схема:
         * показываем только копию
         * для текущего устройства.
         */
        if (
          parsed.recipientDeviceId &&
          parsed.recipientDeviceId !==
            session.deviceId
        ) {
          continue;
        }

        messages.push(
          parsed
        );
      } catch (error) {
        console.error(
          'Invalid message:',
          error
        );
      }
    }

    return res.status(200).json({
      messages
    });
  } catch (error) {
    console.error(
      'GET /api/messages:',
      error?.message ||
        error
    );

    return res.status(500).json({
      error:
        'Ошибка чтения сообщений'
    });
  }
}