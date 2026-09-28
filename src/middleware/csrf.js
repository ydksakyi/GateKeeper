import crypto from 'node:crypto';
import { config } from '../config/index.js';
import { AppError } from '../utils/AppError.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

const safeEqual = (a, b) => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

// Synchroniser token bound to the server-side session. Also creates the (anonymous) session so
// that login and registration are CSRF-protected too.
export function issueCsrfToken(req) {
  req.session.csrfToken ??= crypto.randomBytes(32).toString('base64url');
  return req.session.csrfToken;
}

// Every state-changing /api request must carry the session's token in X-CSRF-Token.
export function csrfProtection(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();
  const expected = req.session?.csrfToken;
  const provided = req.get('x-csrf-token');
  if (!expected || typeof provided !== 'string' || !safeEqual(expected, provided)) {
    return next(new AppError(403, 'CSRF_INVALID', 'Invalid or missing CSRF token.'));
  }
  next();
}

// Defence in depth: a browser-sent Origin on a state-changing request must be one we trust.
export function originCheck() {
  const allowed = new Set([config.appUrl.origin, ...config.corsOrigins]);
  return (req, res, next) => {
    if (SAFE_METHODS.has(req.method)) return next();
    const origin = req.get('origin');
    if (origin && !allowed.has(origin)) {
      return next(new AppError(403, 'ORIGIN_NOT_ALLOWED', 'Request origin is not allowed.'));
    }
    next();
  };
}
