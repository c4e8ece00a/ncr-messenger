import { Redis } from '@upstash/redis';

let redisClient = null;

export function getRedis() {
  if (redisClient) return redisClient;

  const url = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

  if (!url || !token) {
    throw new Error(
      'Redis is not configured. Set UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or KV_REST_API_URL/KV_REST_API_TOKEN in Vercel.'
    );
  }

  redisClient = new Redis({ url, token });
  return redisClient;
}