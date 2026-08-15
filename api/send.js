import { kv } from '@vercel/kv';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  try {
    const { recipient, payload } = req.body || {};

    if (
      !recipient ||
      typeof recipient !== 'string' ||
      !payload ||
      typeof payload !== 'object'
    ) {
      return res.status(400).json({
        error: 'recipient and payload required'
      });
    }

    const key = `messages:${recipient}`;

    await kv.rpush(key, JSON.stringify(payload));

    return res.status(200).json({
      status: 'sent'
    });

  } catch (error) {
    console.error('POST /api/send error:', error);

    return res.status(500).json({
      error: 'Failed to send message'
    });
  }
}
