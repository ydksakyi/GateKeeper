import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/authenticate.js';
import { authRoutes } from './auth.routes.js';
import { accountRoutes } from './account.routes.js';
import { adminRoutes } from './admin.routes.js';

export function apiRouter(limiters) {
  const r = Router();
  r.get('/health', (req, res) => res.json({ status: 'ok' }));
  r.use('/auth', authRoutes(limiters));
  r.use('/account', requireAuth, accountRoutes());
  r.use('/admin', requireAuth, requireRole('admin'), adminRoutes());
  return r;
}
