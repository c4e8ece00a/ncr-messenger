import { getVapidPublicKey } from '../../lib/push.js';
import {
  noStore,
  securityHeaders
} from '../../lib/security.js';

export default async function handler(req, res) {
  securityHeaders(res);
  noStore(res);

  if (req.method !== 'GET') {
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  try {
    return res.status(200).json({
      publicKey: getVapidPublicKey()
    });
  } catch (error) {
    console.error('GET /api/push/config:', error?.message || error);

    return res.status(500).json({
      error: 'Push notifications are not configured'
    });
  }
}