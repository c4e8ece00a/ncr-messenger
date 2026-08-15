# NCR Messenger 3.0

A small educational messenger for Vercel + Upstash Redis.

## Important

The NCR-LWE code in this project is an educational cryptographic prototype. It is **not** suitable for protecting real secrets or production communications. The application uses AES-GCM for the message body, while the NCR-LWE component is a custom demo KEM and has not been security-audited.

## Vercel setup

1. Create/connect an Upstash Redis database through Vercel Marketplace.
2. Make sure these environment variables exist in the Vercel project:
   - `UPSTASH_REDIS_REST_URL`
   - `UPSTASH_REDIS_REST_TOKEN`
3. Push this repository to GitHub and import it into Vercel.
4. Redeploy.

The code also accepts the old `KV_REST_API_URL` / `KV_REST_API_TOKEN` names as a compatibility fallback, but new deployments should use the Upstash names above.

## Local checks

```bash
npm install
npm test
```

The tests verify 100 NCR-LWE key round trips and 100 NCR-LWE + AES-GCM end-to-end encrypt/decrypt cycles.

## Why the old project failed

- It used the deprecated `@vercel/kv` package. Vercel now recommends an external Redis integration and `@upstash/redis`.
- `/api/messages` could be cached as `304`, even though it is a destructive queue-read endpoint.
- The old service worker could cache application requests and make stale client code persist.
- The old decoder encoded bit `1` as `+1`, while decoding with a `Q/4` window; the decision regions overlapped. The new demo encodes `1` near `Q/2` and uses circular distance modulo `Q`.
- The old polling code could create multiple overlapping polling loops.
- The old message queue used a non-atomic read followed by delete. The new endpoint uses Redis `MULTI/EXEC` so the queue read and delete execute atomically.
- Encryption keys were stored under one global localStorage key. The new version stores a keypair per username.
