import crypto from 'node:crypto';
import { getRedis } from '../lib/redis.js';

function normalizeUsername(value) {
  return String(value ?? '').trim();
}

function hashPassword(password, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, 'hex') : crypto.randomBytes(16);
  const derived = crypto.scryptSync(String(password), salt, 64);
  return {
    salt: salt.toString('hex'),
    hash: derived.toString('hex')
  };
}

function verifyPassword(password, stored) {
  if (!stored?.salt || !stored?.hash) return false;
  const derived = crypto.scryptSync(String(password), Buffer.from(stored.salt, 'hex'), 64);
  const expected = Buffer.from(stored.hash, 'hex');
  return expected.length === derived.length && crypto.timingSafeEqual(expected, derived);
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const body = req.body || {};
    const username = normalizeUsername(body.username);
    const password = String(body.password ?? '');
    const publicKey = body.publicKey;

    if (!/^[A-Za-z0-9_.-]{2,32}$/.test(username)) {
      return res.status(400).json({
        error: 'Имя должно содержать 2–32 символа: латинские буквы, цифры, _, -, .'
      });
    }

    if (password.length < 4 || password.length > 128) {
      return res.status(400).json({ error: 'Пароль должен содержать 4–128 символов' });
    }

    if (!publicKey || typeof publicKey !== 'object') {
      return res.status(400).json({ error: 'publicKey is required' });
    }

    const redis = getRedis();
    const userKey = `user:${username}`;
    const publicKeyKey = `publicKey:${username}`;
    const existing = await redis.get(userKey);

    if (existing) {
      if (!verifyPassword(password, existing)) {
        return res.status(401).json({ error: 'Неверное имя или пароль' });
      }

      // The account is device-key based: the current browser's key becomes
      // the active public key after a successful login.
      await redis.set(userKey, {
        ...existing,
        publicKey,
        updatedAt: Date.now()
      });
      await redis.set(publicKeyKey, publicKey);

      return res.status(200).json({ status: 'logged_in' });
    }

    const passwordData = hashPassword(password);
    const user = {
      passwordHash: passwordData.hash,
      passwordSalt: passwordData.salt,
      publicKey,
      createdAt: Date.now(),
      updatedAt: Date.now()
    };

    await redis.set(userKey, user);
    await redis.set(publicKeyKey, publicKey);

    return res.status(200).json({ status: 'registered' });
  } catch (error) {
    console.error('POST /api/auth:', error);
    return res.status(500).json({ error: error?.message || 'Ошибка авторизации' });
  }
}
