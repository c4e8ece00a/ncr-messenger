import { securityHeaders } from '../lib/security.js';

export function withSecurity(handler) {
  return async (req, res) => {
    securityHeaders(res);
    return handler(req, res);
  };
}