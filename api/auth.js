import { kv } from '@vercel/kv';
import crypto from 'crypto';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { username, password, publicKey, subscription } = req.body;
  if (!username || !password || !publicKey) {
    return res.status(400).json({ error: 'username, password and publicKey required' });
  }

  const key = `user:${username}`;

  // Проверяем, существует ли пользователь
  const existingUser = await kv.get(key);

  if (existingUser) {
    // Пользователь существует – проверяем пароль
    const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
    if (existingUser.passwordHash !== passwordHash) {
      return res.status(401).json({ error: 'Invalid password' });
    }
    // Обновляем публичный ключ и подписку (если изменились)
    await kv.set(key, {
      passwordHash,
      publicKey,
      subscription: subscription || existingUser.subscription || null,
    });
    return res.status(200).json({ status: 'logged_in' });
  } else {
    // Новый пользователь – регистрируем
    const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
    await kv.set(key, {
      passwordHash,
      publicKey,
      subscription: subscription || null,
    });
    return res.status(200).json({ status: 'registered' });
  }
}