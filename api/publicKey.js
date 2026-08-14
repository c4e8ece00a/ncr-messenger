import { kv } from '@vercel/kv';

export default async function handler(req, res) {
  const { username } = req.query;
  if (!username) return res.status(400).json({ error: 'username query parameter required' });

  const publicKey = await kv.get(`publicKey:${username}`);
  if (!publicKey) return res.status(404).json({ error: 'User not found' });

  return res.status(200).json({ publicKey });
}
