import { config } from '../config/index.js';
import { AppError, validationError } from '../utils/AppError.js';
import { regenerateSession, destroySession } from '../utils/session.js';
import { issueCsrfToken } from '../middleware/csrf.js';
import * as v from '../validators/index.js';
import * as authService from '../services/auth.service.js';

export function getCsrfToken(req, res) {
  res.json({ csrfToken: issueCsrfToken(req) });
}

export async function register(req, res) {
  const { value, errors } = v.validateRegistration(req.body);
  if (errors) throw validationError(errors);
  await authService.register(value);
  // Identical for new and already-registered emails (prevents account enumeration).
  res.status(201).json({
    message:
      config.emailVerification === 'off'
        ? 'Registration received. You can now sign in.'
        : 'Registration received. Check your inbox to verify your email, then sign in.',
  });
}

export async function login(req, res) {
  const { value, errors } = v.validateLogin(req.body);
  if (errors) throw validationError(errors);

  const user = await authService.verifyCredentials(value);

  // Session fixation defence: a brand-new session id is issued at the moment of authentication.
  await regenerateSession(req);
  req.session.userId = user.id;
  req.session.createdAt = Date.now();
  req.session.cookie.maxAge = value.remember ? config.session.rememberMs : config.session.idleMs;

  res.json({ user, csrfToken: issueCsrfToken(req) });
}

export async function logout(req, res) {
  await destroySession(req); // deletes the row in PostgreSQL, so a stolen cookie is useless afterwards
  res.clearCookie(config.cookie.name, {
    httpOnly: true,
    secure: config.cookie.secure,
    sameSite: config.cookie.sameSite,
    path: '/',
  });
  res.status(204).end();
}

export function me(req, res) {
  res.json({ user: req.user });
}

export async function forgotPassword(req, res) {
  const { value, errors } = v.validateEmailOnly(req.body);
  if (errors) throw validationError(errors);
  await authService.requestPasswordReset(value.email);
  res.json({ message: 'If an account exists for that email, a reset link has been sent.' });
}

export async function resetPassword(req, res) {
  const { value, errors } = v.validateResetPassword(req.body);
  if (errors) throw validationError(errors);
  await authService.resetPassword(value);
  res.json({ message: 'Your password has been reset. You can now sign in.' });
}

export async function verifyEmail(req, res) {
  const { value, errors } = v.validateToken(req.body);
  if (errors) throw validationError(errors);
  await authService.verifyEmail(value.token);
  res.json({ message: 'Your email address has been verified.' });
}

export async function resendVerification(req, res) {
  const { value, errors } = v.validateEmailOnly(req.body);
  if (errors) throw validationError(errors);
  await authService.resendVerification(value.email);
  res.json({ message: 'If that account needs verification, a new link has been sent.' });
}

export { AppError };
