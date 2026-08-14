import { kv } from '@vercel/kv';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { recipient, payload } = req.body;
  if (!recipient || !payload) return res.status(400).json({ error: 'recipient and payload required' });

  await kv.rpush(`messages:${recipient}`, payload);

  return res.status(200).json({ status: 'sent' });
}