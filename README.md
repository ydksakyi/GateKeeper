# Gatekeeper

A session-based authentication system: **Express 5**, **PostgreSQL**, and a dependency-free **vanilla JS** frontend.
Passwords are hashed with **Argon2id**, sessions live in PostgreSQL, and every state-changing request is CSRF-protected.

This is the combined version of GateKeeper, merging the best features from v1 and v2:

| Feature | Source | Rationale |
|---------|--------|-----------|
| Session-based auth (server-side PostgreSQL sessions) | v2 | Strictly superior to stateless JWT: no token revocation issues, server-side control, immediate role/password change propagation |
| Argon2id password hashing | v2 | OWASP-recommended, memory-hard, resists GPU/ASIC attacks |
| Dummy hash verification | v2 | Prevents timing attacks that reveal account existence |
| Password rehash detection | v2 | Transparently upgrades weaker hashes at login |
| Fail-fast validated config | v2 | Startup rejects missing/unsafe settings before any request is handled |
| Multi-layered rate limiting | v2 | Per-IP, per-email, per-account, per-purpose limits; failed-login-only counting prevents lockout |
| CSRF synchronizer tokens + Origin check | v2 | Defense-in-depth against cross-site request forgery |
| Helmet + CSP + HSTS | v2 | Comprehensive browser-side attack surface reduction |
| Unified `auth_tokens` table | v2 | Single table for password-reset and email-verify tokens with atomic consumption |
| Atomic transactions for token operations | v2 | Prevents race conditions in password reset and email verification |
| Session fixation defense | v2 | New session ID issued at login; destroyed on logout |
| `__Host-` cookie prefix | v2 | Browsers enforce Secure + no Domain + root Path |
| SPA frontend with hash routing | v2 | Modern, dependency-free UI with proper XSS-safe rendering |
| Account & admin routes | v2 | Profile updates, user listing, role management |
| Comprehensive test suite | v2 | node:test + Supertest covering auth, authorization, and security |

## Quick start

Requires Node.js 20+ and PostgreSQL 13+.

```bash
npm install
cp .env.example .env            # then edit it (see below)

# create the databases (run in psql as a superuser)
#   CREATE USER gatekeeper WITH PASSWORD 'change_me';
#   CREATE DATABASE gatekeeper OWNER gatekeeper;
#   CREATE DATABASE gatekeeper_test OWNER gatekeeper;

node -p "require('crypto').randomBytes(48).toString('base64url')"   # paste into SESSION_SECRET
npm run db:migrate
npm run create-admin -- you@example.com "Your Name"                # prompts for a password
npm run dev                                                         # http://localhost:3000
```

In development, emails (verification and reset links) are printed to the terminal.

```bash
npm test          # 58 tests; needs TEST_DATABASE_URL (the name must contain "test")
npm run audit     # dependency vulnerability check
```

## Project structure

```
db/schema.sql            Idempotent schema (users, auth_tokens, session)
scripts/                 migrate.js, create-admin.js
src/
  server.js              Startup, graceful shutdown
  app.js                 Middleware order (the security-relevant part)
  config/                Validated environment configuration (fails fast)
  routes/                URL -> middleware -> controller wiring
  controllers/           HTTP concerns: status codes, sessions, cookies
  services/              Auth logic: hashing, tokens, email, register/login/reset
  db/                    All SQL (parameterised); pool + transactions
  middleware/            session, csrf, authenticate/roles, rate limits, headers, errors
  validators/            Server-side validation and sanitisation (authoritative)
public/                  index.html, css/, js/ (api client, validators, UI)
tests/                   node:test + supertest against a real PostgreSQL
```

## Environment variables

Copy `.env.example`. The app refuses to start on missing or unsafe values.

| Variable                                     | Default                 | Notes                                                                                                            |
| -------------------------------------------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `NODE_ENV`                                   | `development`           | `production` enforces the rules marked (prod)                                                                    |
| `PORT`                                       | `3000`                  |                                                                                                                  |
| `APP_URL`                                    | `http://localhost:3000` | Public origin; **https required (prod)**. Used for links in emails and the Origin check                          |
| `DATABASE_URL`                               | required                |                                                                                                                  |
| `TEST_DATABASE_URL`                          | –                       | Tests only. Name must contain `test`                                                                             |
| `DATABASE_SSL`                               | `false`                 | Set `true` for TLS databases                                                                                     |
| `SESSION_SECRET`                             | required                | ≥ 32 chars. Comma-separate to rotate (newest first)                                                              |
| `SESSION_IDLE_MINUTES`                       | `120`                   | Idle timeout (rolling)                                                                                           |
| `SESSION_REMEMBER_DAYS`                      | `14`                    | Idle timeout when "keep me signed in" is ticked                                                                  |
| `SESSION_ABSOLUTE_DAYS`                      | `30`                    | Hard cap regardless of activity                                                                                  |
| `COOKIE_SECURE`                              | `true` in prod          | Must be true (prod). Also enables the `__Host-` cookie prefix                                                    |
| `COOKIE_SAMESITE`                            | `lax`                   | `lax` or `strict`                                                                                                |
| `TRUST_PROXY`                                | `0`                     | Reverse-proxy hops (e.g. `1`). Needed for correct IPs and Secure cookies behind a proxy                          |
| `CORS_ORIGINS`                               | empty                   | Extra browser origins allowed with credentials; empty = same-origin only                                         |
| `ARGON2_MEMORY_KIB` / `ARGON2_TIME_COST`     | `19456` / `2`           | OWASP minimums; enforced (prod)                                                                                  |
| `EMAIL_VERIFICATION`                         | `optional`              | `off`, `optional` (email sent, login allowed), `required` (login blocked until verified)                         |
| `RESET_TOKEN_MINUTES` / `VERIFY_TOKEN_HOURS` | `30` / `24`             | Token lifetimes                                                                                                  |
| `EMAIL_TRANSPORT`                            | `console`               | `smtp` required (prod). Then set `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `EMAIL_FROM` |
| `RATE_LIMIT_ENABLED` and `RL_*`              | on                      | See `.env.example`                                                                                               |

## Database schema

| Table         | Purpose                                  | Key columns                                                                                                                                       |
| ------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `users`       | Accounts                                 | `id uuid`, `name`, `email` (unique, lowercase enforced by CHECK), `password_hash`, `role` (`user`/`admin` CHECK), `email_verified_at`, timestamps |
| `auth_tokens` | Reset and verification tokens            | `user_id` → users (cascade), `purpose`, `token_hash` (unique SHA-256), `expires_at`, `used_at`                                                    |
| `session`     | Server-side sessions (connect-pg-simple) | `sid`, `sess json`, `expire`                                                                                                                      |

## API

All bodies are JSON. Errors look like `{ "error": { "code", "message", "details?" } }`.
Every non-GET request needs the header `X-CSRF-Token` (from `GET /api/auth/csrf`, bound to the session).

| Method & path                        | Auth  | Description                                       | Success                                      | Errors                                              |
| ------------------------------------ | ----- | ------------------------------------------------- | -------------------------------------------- | --------------------------------------------------- |
| `GET /api/health`                    | –     | Liveness                                          | 200                                          |                                                     |
| `GET /api/auth/csrf`                 | –     | Get CSRF token (creates an anonymous session)     | 200                                          |                                                     |
| `POST /api/auth/register`            | –     | `{name,email,password}`                           | 201 (same response even if the email exists) | 422, 429                                            |
| `POST /api/auth/login`               | –     | `{email,password,remember?}` → `{user,csrfToken}` | 200                                          | 401 generic, 403 unverified (if required), 422, 429 |
| `POST /api/auth/logout`              | –     | Destroys the session                              | 204                                          | 403                                                 |
| `GET /api/auth/me`                   | user  | Current user                                      | 200                                          | 401                                                 |
| `POST /api/auth/forgot-password`     | –     | `{email}`; always the same response               | 200                                          | 429                                                 |
| `POST /api/auth/reset-password`      | –     | `{token,password}`; signs out all devices         | 200                                          | 400, 422                                            |
| `POST /api/auth/verify-email`        | –     | `{token}`                                         | 200                                          | 400                                                 |
| `POST /api/auth/resend-verification` | –     | `{email}`; always the same response               | 200                                          | 429                                                 |
| `PATCH /api/account`                 | user  | `{name}`                                          | 200                                          | 401, 422                                            |
| `GET /api/admin/users?page&pageSize` | admin | Paginated users                                   | 200                                          | 401, 403                                            |
| `PATCH /api/admin/users/:id/role`    | admin | `{role}`; cannot change own role                  | 200                                          | 403, 404, 409, 422                                  |

Status codes used: 401 = not signed in, 403 = signed in but forbidden (or CSRF/Origin failure), 422 = validation, 429 = rate limited.

## Security decisions

- **Passwords**: Argon2id (19 MiB, 2 passes, 1 lane), hashes upgraded automatically at login if parameters change. Policy is length-first (10–128 characters) plus a blocklist of common passwords; no composition rules (NIST 800-63B).
- **Sessions**: server-side in PostgreSQL; cookie holds only a signed random id. `HttpOnly`, `Secure` (prod), `SameSite=Lax`, `__Host-` prefix in production. A new session id is issued at login (fixation), sessions are destroyed on logout, idle timeout is rolling, and an absolute lifetime is enforced. The user is reloaded from the database on every request, so role changes and account deletion apply immediately.
- **CSRF**: per-session synchroniser token on every non-GET, plus `Origin` allow-list check, plus JSON-only bodies. `SameSite=Lax` is a further layer, not the only one.
- **XSS**: strict CSP (`script-src 'self'`, no inline script/style), names restricted by an allow-list regex, and the frontend only uses `textContent`/text nodes, never `innerHTML`.
- **SQL injection**: every query uses bound parameters; user input is never concatenated into SQL.
- **Account enumeration**: login errors are identical for unknown email and wrong password (and an unknown email still burns an Argon2 verification); registration and password-reset responses are identical whether or not the account exists; the email-verification check happens only after the password is correct; rate limits behave the same for non-existent emails.
- **Brute force**: failed logins are limited per IP and per submitted email; reset and verification emails are limited per address and per IP; registration and a global API limit apply too.
- **Tokens**: 256-bit random, only the SHA-256 hash is stored, atomic single use, previous tokens are invalidated when a new one is issued. Links put the token in the URL fragment (`/#/reset-password?token=…`) so it is not sent to servers or Referer headers, and the page removes it from the address bar.
- **Headers/CORS**: Helmet (CSP, HSTS in prod, `nosniff`, no-referrer, frame-ancestors none), `Cache-Control: no-store` on the API, CORS allow-list with credentials (empty by default), 10 KB body limit.
- **Secrets**: configuration only from environment; `.env` is git-ignored; startup validation rejects weak secrets and unsafe production settings. Errors returned to clients never include stack traces.

### Known trade-offs

- Registration returns the same message for new and existing emails, so the user is not signed in automatically. This costs a step but avoids leaking which emails are registered.
- Rate-limit counters are in process memory. For more than one instance, use a shared store (for example `rate-limit-redis`) or limit at the proxy.
- Session cleanup in `json` `sess` uses a sequential scan when signing a user out of all devices; add an index on `(sess->>'userId')` (convert `sess` to `jsonb`) if you have very many concurrent sessions.
- No MFA, no "change password while signed in", no account deletion; these are natural next steps.

## Production checklist

1. Serve over HTTPS only; set `NODE_ENV=production`, `APP_URL=https://…`, `TRUST_PROXY=<hops>`.
2. Set a strong `SESSION_SECRET`, real `SMTP_*`, and `DATABASE_SSL=true` for remote databases.
3. Run `npm run db:migrate` (or adopt a migration tool) and `npm run create-admin`.
4. Use a least-privilege database user (no superuser, no DDL rights at runtime if you migrate separately).
5. Run `npm run audit` in CI and keep dependencies updated.
