import { Router } from 'express';
import * as c from '../controllers/account.controller.js';

// Mounted behind requireAuth in routes/index.js.
export function accountRoutes() {
  const r = Router();
  r.patch('/', c.updateProfile);
  return r;
}
