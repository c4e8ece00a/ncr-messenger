import { getRedis } from '../lib/redis.js';
import {
  securityHeaders,
  noStore,
  requireSession,
  normalizeUsername,
  validUsername
} from '../lib/security.js';

export default async function handler(req, res) {
  securityHeaders(res);
  noStore(res);

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const redis = getRedis();
    const session = await requireSession(req, res, redis);
    if (!session) return;

    const username = normalizeUsername(req.query?.username);

    if (!validUsername(username)) {
      return res.status(400).json({ error: 'Некорректное имя пользователя' });
    }

    const deviceIds = await redis.smembers(`devices:${username}`);
    const devices = [];

    for (const deviceId of deviceIds || []) {
      const raw = await redis.get(`device:${username}:${deviceId}`);
      if (!raw) continue;

      try {
        const device = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (device?.deviceId && device?.publicKey) {
          devices.push({
            deviceId: device.deviceId,
            publicKey: device.publicKey
          });
        }
      } catch (error) {
        console.error('Invalid device record:', error);
      }
    }

    /*
     * Compatibility with accounts created before 3.3.0.
     * The legacy key is exposed as one temporary device only when
     * no new device registry exists. New logins immediately create
     * their own device record through /api/auth.
     */
    if (devices.length === 0) {
      const legacyKey = await redis.get(`publicKey:${username}`);
      if (legacyKey) {
        return res.status(200).json({
          devices: [{
            deviceId: 'legacy',
            publicKey: legacyKey
          }]
        });
      }
    }

    if (devices.length === 0) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    return res.status(200).json({ devices });
  } catch (error) {
    console.error('GET /api/publicKey:', error?.message || error);
    return res.status(500).json({ error: 'Ошибка базы данных' });
  }
}
