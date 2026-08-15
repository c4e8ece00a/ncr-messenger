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

    const publicKey = await redis.get(`publicKey:${username}`);

    if (!publicKey) {
      return res.status(404).json({
        error: 'Пользователь не найден'
      });
    }

    return res.status(200).json({
      publicKey
    });

  } catch (error) {
    console.error('PUBLIC KEY ERROR:', error);

    return res.status(500).json({
      error: 'Ошибка сервера'
    });
  }
}
