import crypto from 'node:crypto';

export const USERNAME_RE = /^[A-Za-z0-9_]{3,32}$/;
export const DEVICE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const MAX_PASSWORD_LENGTH = 128;
export const MAX_MESSAGE_BYTES = 65536;

export function normalizeUsername(value) {
  return String(value ?? '').trim();
}

export function validUsername(username) {
  return USERNAME_RE.test(username);
}

export function validDeviceId(deviceId) {
  return typeof deviceId === 'string' && DEVICE_ID_RE.test(deviceId);
}

export function getCookie(req, name) {
  const header = req.headers?.cookie || '';

  for (const part of header.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return decodeURIComponent(rest.join('='));
  }

  return null;
}

export function newToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function newDeviceId() {
  return crypto.randomUUID();
}

export function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function setSessionCookie(res, token, maxAge = 60 * 60 * 24 * 30) {
  res.setHeader(
    'Set-Cookie',
    `ncr_session=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`
  );
}

export function clearSessionCookie(res) {
  res.setHeader(
    'Set-Cookie',
    'ncr_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict'
  );
}

export function jsonBodySize(req) {
  const length = Number(req.headers?.['content-length'] || 0);
  return Number.isFinite(length) ? length : 0;
}

export function noStore(res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
}

export function securityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
  );
}

export async function requireSession(req, res, redis) {
  const token = getCookie(req, 'ncr_session');

  if (!token) {
    res.status(401).json({ error: 'Необходима авторизация' });
    return null;
  }

  const tokenHash = sha256(token);
  const session = await redis.get(`session:${tokenHash}`);

  if (!session) {
    clearSessionCookie(res);
    res.status(401).json({ error: 'Сессия истекла' });
    return null;
  }

  let parsed;

  try {
    parsed = typeof session === 'string' ? JSON.parse(session) : session;
  } catch {
    clearSessionCookie(res);
    res.status(401).json({ error: 'Недействительная сессия' });
    return null;
  }

  if (!parsed?.username || !validUsername(parsed.username) || !validDeviceId(parsed.deviceId)) {
    clearSessionCookie(res);
    res.status(401).json({ error: 'Недействительная сессия' });
    return null;
  }

  return parsed;
}

export function requireSameOrigin(req, res) {
  const origin = req.headers?.origin;
  if (!origin) return true;

  const host = req.headers?.host;

  try {
    const url = new URL(origin);
    if (url.host !== host) {
      res.status(403).json({ error: 'Недопустимый origin' });
      return false;
    }
    return true;
  } catch {
    res.status(403).json({ error: 'Недопустимый origin' });
    return false;
  }
}

export async function rateLimit(redis, key, limit, windowSeconds) {
  const bucket = `rl:${key}`;
  const count = await redis.incr(bucket);
  if (count === 1) await redis.expire(bucket, windowSeconds);
  return { allowed: count <= limit, count };
}
