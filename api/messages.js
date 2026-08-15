import { redis } from './_redis.js';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  try {
    const username = String(req.query?.username || '').trim();

    if (!username) {
      return res.status(400).json({
        error: 'username query parameter required'
      });
    }

    const key = `messages:${username}`;

    const rawMessages = await redis.lrange(key, 0, -1);

    const messages = [];

    for (const raw of rawMessages) {
      try {
        const message =
          typeof raw === 'string'
            ? JSON.parse(raw)
            : raw;

        if (message && message.id && message.payload) {
          messages.push(message);
        }
      } catch (error) {
        console.error(
          'INVALID MESSAGE IN QUEUE:',
          error
        );
      }
    }

    return res.status(200).json({
      messages
    });

  } catch (error) {
    console.error('MESSAGES ERROR:', error);

    return res.status(500).json({
      error: 'Ошибка получения сообщений'
    });
  }
}
