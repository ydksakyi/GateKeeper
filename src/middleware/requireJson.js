import { AppError } from '../utils/AppError.js';

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

// Requests that carry a body must be JSON. Cross-site HTML forms cannot send application/json
// without a CORS preflight, which is one more layer against CSRF.
export function requireJson(req, res, next) {
  const hasBody = req.headers['transfer-encoding'] !== undefined || Number(req.headers['content-length'] ?? 0) > 0;
  if (WRITE_METHODS.has(req.method) && hasBody && !req.is('application/json')) {
    return next(new AppError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Content-Type must be application/json.'));
  }
  next();
}
