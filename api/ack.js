import { redis } from './_redis.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  try {
    const {
      username,
      messageId
    } = req.body || {};

    if (!username || !messageId) {
      return res.status(400).json({
        error: 'username and messageId required'
      });
    }

    const key = `messages:${String(username).trim()}`;

    const rawMessages = await redis.lrange(
      key,
      0,
      -1
    );
    
    let removed = 0;

    for (const raw of rawMessages) {
      try {
        const message =
          typeof raw === 'string'
            ? JSON.parse(raw)
            : raw;

        if (message?.id === messageId) {
          removed += await redis.lrem(
            key,
            1,
            raw
          );

          break;
        }

      } catch (error) {
        console.error(
          'ACK PARSE ERROR:',
          error
        );
      }
    }

    return res.status(200).json({
      status: removed > 0
        ? 'acknowledged'
        : 'already_removed',
      removed
    });

  } catch (error) {
    console.error('ACK ERROR:', error);

    return res.status(500).json({
      error: 'Ошибка подтверждения сообщения'
    });
  }
}
