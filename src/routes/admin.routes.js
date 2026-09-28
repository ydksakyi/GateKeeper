import { Router } from 'express';
import * as c from '../controllers/admin.controller.js';

// Mounted behind requireAuth + requireRole('admin') in routes/index.js.
export function adminRoutes() {
  const r = Router();
  r.get('/users', c.listUsers);
  r.patch('/users/:id/role', c.updateRole);
  return r;
}
