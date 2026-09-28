import helmet from 'helmet';
import cors from 'cors';
import { config } from '../config/index.js';

// Strict CSP: only same-origin scripts and styles, no inline anything. This is the main XSS backstop.
export function securityHeaders() {
  const directives = {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'"],
    imgSrc: ["'self'", 'data:'],
    fontSrc: ["'self'"],
    connectSrc: ["'self'"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"],
  };
  if (config.isProd) directives.upgradeInsecureRequests = [];

  return helmet({
    contentSecurityPolicy: { useDefaults: false, directives },
    hsts: config.isProd ? { maxAge: 31_536_000, includeSubDomains: true } : false,
    referrerPolicy: { policy: 'no-referrer' },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
  });
}

// Same-origin by default. Only origins listed in CORS_ORIGINS receive CORS headers.
export function corsMiddleware() {
  const allowed = new Set(config.corsOrigins);
  return cors({
    origin: (origin, cb) => cb(null, Boolean(origin) && allowed.has(origin)),
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'X-CSRF-Token'],
    maxAge: 600,
    optionsSuccessStatus: 204,
  });
}

// Auth responses must never be cached by browsers or shared proxies.
export function noStore(req, res, next) {
  res.set('Cache-Control', 'no-store');
  next();
}
