import { kv } from '@vercel/kv';

export default async function handler(req, res) {
  const { username } = req.query;
  if (!username) return res.status(400).json({ error: 'username query parameter required' });

  const key = `messages:${username}`;
  const messages = await kv.lrange(key, 0, -1);
  if (messages.length > 0) {
    await kv.del(key);
  }

  return res.status(200).json({ messages });
}
