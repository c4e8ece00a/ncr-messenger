import { getRedis } from '../lib/redis.js';
import { requireSession, noStore, securityHeaders } from '../lib/security.js';

export default async function handler(req, res) {
  securityHeaders(res);
  noStore(res);
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const session = await requireSession(req, res, getRedis());
    if (!session) return;
    return res.status(200).json({ username: session.username });
  } catch (error) {
    console.error('GET /api/session:', error?.message || error);
    return res.status(500).json({ error: 'Ошибка проверки сессии' });
  }
}