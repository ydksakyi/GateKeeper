import { config } from '../config/index.js';
import * as users from '../db/users.js';
import { AppError } from '../utils/AppError.js';
import { regenerateSession } from '../utils/session.js';

// Loads the current user from the session on every request, so role changes, deletions and
// password resets take effect immediately. Enforces the absolute session lifetime.
export async function authenticate(req, res, next) {
  const s = req.session;
  if (!s?.userId) return next();

  const expired = !Number.isFinite(s.createdAt) || Date.now() - s.createdAt > config.session.absoluteMs;
  const user = expired ? null : await users.findById(s.userId);
  if (!user) {
    await regenerateSession(req); // drop the stale session, continue as anonymous
    return next();
  }
  req.user = user;
  next();
}

export function requireAuth(req, res, next) {
  if (!req.user) return next(new AppError(401, 'UNAUTHENTICATED', 'Authentication required.'));
  next();
}

export const requireRole =
  (...roles) =>
  (req, res, next) => {
    if (!req.user) return next(new AppError(401, 'UNAUTHENTICATED', 'Authentication required.'));
    if (!roles.includes(req.user.role)) {
      return next(new AppError(403, 'FORBIDDEN', 'You do not have permission to perform this action.'));
    }
    next();
  };
