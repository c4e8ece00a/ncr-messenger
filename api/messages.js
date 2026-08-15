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

  // Очень важно:
  // сообщения нельзя отдавать из HTTP-кэша.
  res.setHeader(
    'Cache-Control',
    'no-store, no-cache, must-revalidate, proxy-revalidate'
  );

  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  try {
    const key = `messages:${username}`;

    const messages = await kv.lrange(key, 0, -1);

    // После успешного чтения очищаем очередь.
    if (messages.length > 0) {
      await kv.del(key);
    }

    return res.status(200).json({
      messages: Array.isArray(messages) ? messages : []
    });

  } catch (error) {
    console.error('GET /api/messages error:', error);

    return res.status(500).json({
      error: 'Failed to read messages'
    });
  }
}
