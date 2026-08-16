# NCR Messenger 3.1 — Security Hardening

This version is based on NCR Messenger 3.0 and adds Stage 1 security hardening.

## Added

- Argon2id password hashing.
- Secure HttpOnly/Secure/SameSite session cookies.
- Server-side session storage with hashed session tokens.
- API authorization: sender/user identity comes from the session, not from request JSON/query parameters.
- Rate limiting for login, public-key lookup, and sending.
- Origin checks for state-changing requests.
- Strict username and payload validation.
- Security headers and HSTS.
- No-store headers on API endpoints.
- Real logout endpoint.
- One-time migration path for legacy `sha256:<hash>` password records.
- API polling no longer accepts a username and therefore cannot read another user's queue just by changing a query parameter.

## Environment variables

Required:

- `UPSTASH_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN`

The legacy `KV_REST_API_URL` / `KV_REST_API_TOKEN` names are accepted only as compatibility fallback.

## Important security limitation

The NCR-LWE component remains an educational cryptographic prototype and is NOT production-grade cryptography. Stage 1 hardens authentication and the API; it does not turn the custom NCR-LWE construction into audited cryptography.

## Existing users

New passwords are stored with Argon2id.

If an existing user record contains `sha256:<hash>`, a successful login upgrades it to Argon2id automatically.

## Deploy

1. Replace the current project files with this version.
2. Install dependencies.
3. Ensure the two Upstash environment variables exist in Vercel.
4. Deploy.
5. Test login, two-user messaging, logout, and expired-session behavior.

## Important migration note

Because this version intentionally changes the API contract:

- `/api/messages` no longer accepts `?username=...`.
- `/api/send` no longer accepts `sender`.
- The browser sends credentials by same-origin cookie.

Do not keep an older cached `app.js` open while testing. The service worker cache name is bumped to `ncr-messenger-v3-1`.
