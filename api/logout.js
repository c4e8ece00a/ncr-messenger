import { getRedis } from '../lib/redis.js';
import { clearSessionCookie, getCookie, sha256, noStore, requireSameOrigin, securityHeaders } from '../lib/security.js';

export default async function handler(req, res) {
  securityHeaders(res);
  noStore(res);
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (!requireSameOrigin(req, res)) return;

  try {
    const token = getCookie(req, 'ncr_session');
    if (token) await getRedis().del(`session:${sha256(token)}`);
    clearSessionCookie(res);
    return res.status(200).json({ status: 'ok' });
  } catch (error) {
    console.error('POST /api/logout:', error?.message || error);
    clearSessionCookie(res);
    return res.status(200).json({ status: 'ok' });
  }
}