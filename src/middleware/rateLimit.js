import rateLimit from 'express-rate-limit';

const handler = (req, res) =>
  res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many requests. Please try again later.' } });

const make = (opts) => rateLimit({ standardHeaders: 'draft-7', legacyHeaders: false, handler, ...opts });

// Keyed by the submitted email (not the IP) so a distributed attack on one account is still throttled.
// Works identically for emails that do not exist, so it leaks nothing.
const emailKey = (req) =>
  typeof req.body?.email === 'string' ? `email:${req.body.email.trim().toLowerCase().slice(0, 254)}` : `ip:${req.ip}`;

// NOTE: the default in-memory store is per process. Behind several instances, use a shared store
// (for example rate-limit-redis) or enforce limits at the proxy as well.
export function buildRateLimiters(rl) {
  const pass = (req, res, next) => next();
  if (!rl.enabled) {
    return { global: pass, register: pass, loginIp: pass, loginAccount: pass, passwordReset: pass, emailAccount: pass, verification: pass };
  }
  return {
    global: make({ windowMs: rl.global.windowMs, limit: rl.global.limit }),
    register: make({ windowMs: rl.register.windowMs, limit: rl.register.limit }),
    // Only failed attempts (status >= 400) count, so normal users are never locked out by logging in.
    loginIp: make({ windowMs: rl.login.windowMs, limit: rl.login.ipLimit, skipSuccessfulRequests: true }),
    loginAccount: make({ windowMs: rl.login.windowMs, limit: rl.login.accountLimit, skipSuccessfulRequests: true, keyGenerator: emailKey }),
    passwordReset: make({ windowMs: rl.passwordReset.windowMs, limit: rl.passwordReset.limit }),
    emailAccount: make({ windowMs: rl.emailAccount.windowMs, limit: rl.emailAccount.limit, keyGenerator: emailKey }),
    verification: make({ windowMs: rl.verification.windowMs, limit: rl.verification.limit }),
  };
}
