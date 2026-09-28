import { Router } from 'express';
import { requireAuth } from '../middleware/authenticate.js';
import * as c from '../controllers/auth.controller.js';

export function authRoutes(l) {
  const r = Router();
  r.get('/csrf', c.getCsrfToken);
  r.get('/me', requireAuth, c.me);

  r.post('/register', l.register, c.register);
  r.post('/login', l.loginIp, l.loginAccount, c.login);
  r.post('/logout', c.logout);

  r.post('/forgot-password', l.passwordReset, l.emailAccount, c.forgotPassword);
  r.post('/reset-password', l.passwordReset, c.resetPassword);
  r.post('/verify-email', l.verification, c.verifyEmail);
  r.post('/resend-verification', l.verification, l.emailAccount, c.resendVerification);
  return r;
}
