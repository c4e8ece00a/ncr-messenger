import { kv } from '@vercel/kv';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { username, publicKey, subscription } = req.body;
  if (!username || !publicKey) return res.status(400).json({ error: 'username and publicKey required' });

  const exists = await kv.exists(`publicKey:${username}`);
  if (exists) return res.status(409).json({ error: 'Username already taken' });

  await kv.set(`publicKey:${username}`, JSON.stringify(publicKey));
  if (subscription) {
    await kv.set(`subscription:${username}`, JSON.stringify(subscription));
  }
  return res.status(200).json({ status: 'ok' });
}