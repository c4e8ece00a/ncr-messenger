import { getRedis } from '../lib/redis.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const username = String(req.query?.username ?? '').trim();

  if (!username) {
    return res.status(400).json({ error: 'username query parameter required' });
  }

  try {
    const redis = getRedis();
    const publicKey = await redis.get(`publicKey:${username}`);

    if (!publicKey) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    return res.status(200).json({ publicKey });
  } catch (error) {
    console.error('GET /api/publicKey:', error);
    return res.status(500).json({ error: error?.message || 'Ошибка базы данных' });
  }
}
