import { kv } from '@vercel/kv';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  const { username } = req.query;

  if (!username || typeof username !== 'string') {
    return res.status(400).json({
      error: 'username query parameter required'
    });
  }

  // Никогда не кэшируем очередь сообщений.
  res.setHeader(
    'Cache-Control',
    'no-store, no-cache, must-revalidate, proxy-revalidate'
  );
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  try {
    const key = `messages:${username}`;

    const rawMessages = await kv.lrange(key, 0, -1);

    const messages = [];

    for (const raw of rawMessages) {
      try {
        if (typeof raw === 'string') {
          messages.push(JSON.parse(raw));
        } else {
          messages.push(raw);
        }
      } catch (error) {
        console.error('Invalid stored message:', raw);
      }
    }

    // Очищаем очередь только после успешного чтения.
    if (rawMessages.length > 0) {
      await kv.del(key);
    }

    return res.status(200).json({
      messages
    });

  } catch (error) {
    console.error('GET /api/messages error:', error);

    return res.status(500).json({
      error: 'Failed to read messages'
    });
  }
}
