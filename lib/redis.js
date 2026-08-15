import { Redis } from '@upstash/redis';

let redisClient = null;

export function getRedis() {
  if (redisClient) return redisClient;

  // New Upstash/Vercel integration variables.
  const url = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

  if (!url || !token) {
    throw new Error(
      'Redis is not configured. Set UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN in Vercel.'
    );
  }

  redisClient = new Redis({ url, token });
  return redisClient;
}
