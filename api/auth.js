import { kv } from '@vercel/kv';
import crypto from 'crypto';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { username, password, publicKey, subscription } = req.body;
  if (!username || !password || !publicKey) {
    return res.status(400).json({ error: 'username, password and publicKey required' });
  }

  const userKey = `user:${username}`;
  const pubKeyKey = `publicKey:${username}`;
  const passwordHash = crypto.createHash('sha256').update(password).digest('hex');

  const existingUser = await kv.get(userKey);

  if (existingUser) {
    // Вход: проверяем пароль
    if (existingUser.passwordHash !== passwordHash) {
      return res.status(401).json({ error: 'Invalid password' });
    }
    // Обновляем публичный ключ и подписку
    await kv.set(userKey, {
      passwordHash,
      publicKey,
      subscription: subscription || existingUser.subscription || null,
    });
    await kv.set(pubKeyKey, publicKey);
    return res.status(200).json({ status: 'logged_in' });
  } else {
    // Регистрация нового пользователя
    await kv.set(userKey, {
      passwordHash,
      publicKey,
      subscription: subscription || null,
    });
    await kv.set(pubKeyKey, publicKey);
    return res.status(200).json({ status: 'registered' });
  }
}
