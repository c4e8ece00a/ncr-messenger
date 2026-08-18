import { getRedis } from '../lib/redis.js';

import {
  noStore,
  securityHeaders,
  requireSession,
  requireSameOrigin
} from '../lib/security.js';

export default async function handler(req, res) {
  securityHeaders(res);
  noStore(res);

  if (req.method !== 'GET') {
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  if (!requireSameOrigin(req, res)) {
    return;
  }

  try {
    const redis = getRedis();

    const session = await requireSession(
      req,
      res,
      redis
    );

    if (!session) {
      return;
    }

    const username = session.username;
    const key = `messages:${username}`;

    /*
     * ВАЖНО:
     *
     * Здесь мы только читаем очередь.
     * Ничего не удаляем.
     *
     * Клиент должен сначала расшифровать сообщение
     * и затем подтвердить его через /api/ack.
     */
    const rawMessages = await redis.lrange(
      key,
      0,
      -1
    );

    const messages = [];

    for (const raw of rawMessages) {
      try {
        const parsed =
          typeof raw === 'string'
            ? JSON.parse(raw)
            : raw;

        if (
          parsed &&
          typeof parsed === 'object' &&
          parsed.id &&
          parsed.sender &&
          parsed.recipient
        ) {
          messages.push(parsed);
        }
      } catch (error) {
        /*
         * Повреждённый элемент очереди не должен
         * ломать выдачу остальных сообщений.
         */
        console.error(
          'Invalid message in Redis:',
          error?.message || error
        );
      }
    }

    return res.status(200).json({
      messages
    });
  } catch (error) {
    console.error(
      'GET /api/messages:',
      error?.message || error
    );

    return res.status(500).json({
      error: 'Ошибка чтения сообщений'
    });
  }
}