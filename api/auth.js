import { hash, verify } from '@node-rs/argon2';
import { getRedis } from '../lib/redis.js';
import {
  MAX_PASSWORD_LENGTH,
  normalizeUsername,
  validUsername,
  validDeviceId,
  newToken,
  sha256,
  setSessionCookie,
  noStore,
  requireSameOrigin,
  rateLimit,
  jsonBodySize,
  securityHeaders
} from '../lib/security.js';

const SESSION_TTL = 60 * 60 * 24 * 30;
const MIN_PASSWORD_LENGTH = 8;

function genericAuthError(res) {
  return res.status(401).json({ error: 'Неверные учетные данные' });
}

async function createPasswordHash(password) {
  return hash(password, {
    algorithm: 'argon2id',
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1
  });
}

function sameJson(a, b) {
  try {
    return JSON.stringify(a) === JSON.stringify(b);
  } catch {
    return false;
  }
}

async function ensureDevice(redis, username, deviceId, publicKey) {
  const deviceKey = `device:${username}:${deviceId}`;
  const existingDevice = await redis.get(deviceKey);

  if (existingDevice) {
    const device = typeof existingDevice === 'string'
      ? JSON.parse(existingDevice)
      : existingDevice;

    if (!device?.publicKey || !sameJson(device.publicKey, publicKey)) {
      const error = new Error('Ключ этого устройства не совпадает с сохранённым ключом');
      error.code = 'DEVICE_KEY_MISMATCH';
      throw error;
    }

    await redis.sadd(`devices:${username}`, deviceId);
    return;
  }

  await redis.set(deviceKey, JSON.stringify({
    username,
    deviceId,
    publicKey,
    createdAt: Date.now(),
    updatedAt: Date.now()
  }));

  await redis.sadd(`devices:${username}`, deviceId);
}

export default async function handler(req, res) {
  securityHeaders(res);
  noStore(res);

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!requireSameOrigin(req, res)) return;

  if (jsonBodySize(req) > 16 * 1024) {
    return res.status(413).json({ error: 'Слишком большой запрос' });
  }

  try {
    const body = req.body || {};
    const username = normalizeUsername(body.username);
    const password = String(body.password ?? '');
    const publicKey = body.publicKey;
    const deviceId = String(body.deviceId ?? '').trim();

    if (
      !validUsername(username) ||
      password.length < MIN_PASSWORD_LENGTH ||
      password.length > MAX_PASSWORD_LENGTH ||
      !validDeviceId(deviceId) ||
      !publicKey ||
      typeof publicKey !== 'object'
    ) {
      return genericAuthError(res);
    }

    const redis = getRedis();
    const ip = req.headers['x-forwarded-for'] || 'unknown';
    const rl = await rateLimit(redis, `login:${username}:${ip}`, 5, 300);

    if (!rl.allowed) {
      return res.status(429).json({ error: 'Слишком много попыток. Попробуйте позже.' });
    }

    const userKey = `user:${username}`;
    const existing = await redis.get(userKey);

    if (!existing) {
      const passwordHash = await createPasswordHash(password);

      await redis.set(userKey, JSON.stringify({
        username,
        passwordHash,
        createdAt: Date.now()
      }));
    } else {
      let user;

      try {
        user = typeof existing === 'string' ? JSON.parse(existing) : existing;
      } catch {
        return genericAuthError(res);
      }

      let valid = false;

      if (user?.passwordHash) {
        try {
          valid = await verify(user.passwordHash, password);
        } catch (error) {
          console.error('Password verification:', error?.message || error);
        }
      }

      if (
        !valid &&
        typeof user?.passwordHash === 'string' &&
        user.passwordHash.startsWith('sha256:')
      ) {
        const legacy = sha256(password);

        if (legacy === user.passwordHash.slice(7)) {
          user.passwordHash = await createPasswordHash(password);
          await redis.set(userKey, JSON.stringify(user));
          valid = true;
        }
      }

      if (!valid) return genericAuthError(res);
    }

    await ensureDevice(redis, username, deviceId, publicKey);

    const token = newToken(32);
    const tokenHash = sha256(token);
    const session = {
      username,
      deviceId,
      createdAt: Date.now()
    };

    await redis.set(
      `session:${tokenHash}`,
      JSON.stringify(session),
      { ex: SESSION_TTL }
    );

    setSessionCookie(res, token, SESSION_TTL);

    return res.status(200).json({
      status: 'ok',
      username,
      deviceId
    });
  } catch (error) {
    if (error?.code === 'DEVICE_KEY_MISMATCH') {
      return res.status(409).json({ error: error.message });
    }

    console.error('POST /api/auth:', error?.message || error);
    return res.status(500).json({ error: 'Ошибка авторизации' });
  }
}
