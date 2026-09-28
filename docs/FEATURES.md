# Gatekeeper Features

## Table of Contents

1. [Feature Overview](#feature-overview)
2. [Authentication & User Management](#authentication--user-management)
3. [Password Security](#password-security)
4. [Session Management](#session-management)
5. [Email Verification](#email-verification)
6. [Password Reset](#password-reset)
7. [Role-Based Access Control (RBAC)](#role-based-access-control-rbac)
8. [CSRF Protection](#csrf-protection)
9. [Rate Limiting](#rate-limiting)
10. [Security Headers & CSP](#security-headers--csp)
11. [Account Enumeration Prevention](#account-enumeration-prevention)
12. [Token Security](#token-security)
13. [Database-Backed Sessions](#database-backed-sessions)
14. [Frontend Features](#frontend-features)
15. [Configuration & Validation](#configuration--validation)
16. [Observability & Operations](#observability--operations)
17. [Feature Comparison Matrix](#feature-comparison-matrix)

---

## Feature Overview

Gatekeeper is not just an authentication library — it is a **complete, security-hardened authentication system** with features designed to protect users and developers from the most common and dangerous web application vulnerabilities.

| Category      | Feature                        | Description                                                   |
| ------------- | ------------------------------ | ------------------------------------------------------------- |
| **Auth**      | Registration & Login           | Secure user registration and login with session issuance.     |
| **Auth**      | Logout                         | Explicit session destruction.                                 |
| **Auth**      | Profile Management             | Users can update their display name.                          |
| **Auth**      | Email Verification             | Optional or mandatory email verification with secure tokens.  |
| **Auth**      | Password Reset                 | Secure, single-use password reset via email.                  |
| **Security**  | Argon2id Hashing               | State-of-the-art password hashing with automatic rehashing.   |
| **Security**  | CSRF Protection                | Per-session synchronizer tokens + Origin validation.          |
| **Security**  | Rate Limiting                  | Multi-layered rate limiting on all sensitive endpoints.       |
| **Security**  | Security Headers               | Helmet-based CSP, HSTS, X-Frame-Options, etc.                 |
| **Security**  | XSS Prevention                 | Strict CSP, no `innerHTML`, input sanitization.               |
| **Security**  | SQL Injection Prevention       | 100% parameterized queries.                                   |
| **Security**  | Account Enumeration Prevention | Uniform responses and timing for all auth operations.         |
| **Sessions**  | PostgreSQL-Backed              | Server-side sessions with no client-side sensitive data.      |
| **Sessions**  | Cookie Hardening               | `Secure`, `HttpOnly`, `SameSite`, `__Host-` prefix.           |
| **Sessions**  | Fixation Prevention            | New session ID on login.                                      |
| **Sessions**  | Rolling Idle Timeout           | Session lifetime extends on activity.                         |
| **Sessions**  | Absolute Timeout               | Hard cap on session lifetime.                                 |
| **RBAC**      | User & Admin Roles             | Built-in role-based access control.                           |
| **RBAC**      | Admin API                      | List users, change roles (with self-protection).              |
| **Tokens**    | Secure Generation              | 256-bit random tokens (cryptographically secure).             |
| **Tokens**    | Hash-Only Storage              | Only SHA-256 hashes stored; raw tokens never persisted.       |
| **Tokens**    | Single-Use                     | Tokens are consumed on first use and cannot be reused.        |
| **Tokens**    | Atomic Invalidation            | New tokens invalidate previous ones.                          |
| **Tokens**    | URL Fragment Delivery          | Tokens delivered in `#/` fragment to prevent Referer leakage. |
| **Transport** | CORS                           | Allow-list based CORS with credential support.                |
| **Transport** | No-Store Cache                 | `Cache-Control: no-store` on all API responses.               |
| **Transport** | Body Size Limit                | 10 KB JSON payload limit.                                     |
| **Frontend**  | Vanilla JS SPA                 | No framework dependencies; lightweight and fast.              |
| **Frontend**  | Client-Side Validation         | Real-time form validation mirroring server rules.             |
| **Frontend**  | CSRF-Aware API Client          | Automatic CSRF token injection and URL fragment cleanup.      |
| **Config**    | Fail-Fast Validation           | Application refuses to start on unsafe/missing config.        |
| **Config**    | Environment-Only               | No hardcoded secrets; configuration via env vars.             |
| **Config**    | Flexible Email Transport       | Console (dev) or SMTP (prod) with full SMTP support.          |

---

## Authentication & User Management

### Registration

Users can create accounts through a secure registration endpoint. Key security features:

- **Input Validation**: Name, email, and password are validated server-side.
- **Email Normalization**: Emails are stored in lowercase using a `CHECK` constraint.
- **Uniform Response**: The same response is returned whether the email is new or existing, preventing account enumeration.
- **Timing Consistency**: Password hashing is performed regardless of whether the email exists, maintaining consistent response times.
- **Optional Email Verification**: If enabled, a verification email is sent for new accounts.

### Login

The login endpoint enforces multiple security controls:

- **Credential Verification**: Email and password are verified against the database.
- **Dummy Hash for Unknown Emails**: For non-existent emails, a CPU-intensive Argon2 verification is performed against a pre-computed dummy hash to match the timing of real verifications.
- **Email Verification Gate**: If `EMAIL_VERIFICATION=required`, unverified accounts are rejected after the password is verified (preventing enumeration via this endpoint).
- **Automatic Hash Upgrade**: If the stored password hash uses weaker parameters, it is transparently upgraded on successful login.
- **New Session Issuance**: A new session ID is generated on login, preventing session fixation attacks.

### Logout

- **Session Destruction**: The current session is destroyed in the database.
- **Cookie Clearing**: The session cookie is cleared from the browser.

### Profile Management

Authenticated users can update their display name via `PATCH /api/account`. The name is validated against an allow-list regex to prevent XSS.

---

## Password Security

### Argon2id Hashing

Gatekeeper uses **Argon2id**, the hybrid variant of Argon2 that combines resistance to both side-channel attacks (Argon2i) and GPU/parallel attacks (Argon2d). It is the winner of the Password Hashing Competition (PHC) and is recommended by OWASP.

**Default Parameters**:

- **Memory**: 19 MiB (`ARGON2_MEMORY_KIB=19456`)
- **Time Cost**: 2 passes (`ARGON2_TIME_COST=2`)
- **Parallelism**: 1 lane (`parallelism=1`)

These parameters meet or exceed OWASP minimums and provide strong resistance to both offline and online attacks.

### Password Policy

- **Length-First Approach**: Minimum 10 characters, maximum 128 characters.
- **No Composition Rules**: No forced uppercase, lowercase, numbers, or symbols (NIST SP 800-63B compliant).
- **Common Password Blocklist**: A blocklist of commonly used passwords is enforced (can be extended).
- **Rationale**: Length is the primary determinant of password strength. Composition rules lead to predictable patterns that attackers can exploit.

### Automatic Rehashing

When a user logs in with a password hashed using weaker parameters (e.g., before an upgrade), the system:

1. Detects the weaker hash using `argon2.needsRehash()`.
2. Re-hashes the password with the current parameters.
3. Updates the `password_hash` in the database.

This ensures all users benefit from strengthened parameters over time without requiring a password reset.

### Timing Attack Mitigation

For unknown email addresses, the system:

1. Looks up the email in the database.
2. If not found, performs an Argon2 verification against a **pre-computed dummy hash**.
3. Returns the same error as for a wrong password.

This ensures the response time is indistinguishable between valid and invalid emails, preventing attackers from determining which emails are registered by measuring response times.

---

## Session Management

### Server-Side Storage

Sessions are stored in PostgreSQL using `connect-pg-simple`. The session cookie contains only a signed, random session ID — no sensitive data is stored client-side.

### Cookie Security

Session cookies are configured with the following attributes:

| Attribute        | Value         | Purpose                                                                                                           |
| ---------------- | ------------- | ----------------------------------------------------------------------------------------------------------------- |
| `HttpOnly`       | `true`        | Prevents JavaScript access; mitigates XSS session theft.                                                          |
| `Secure`         | `true` (prod) | Sent only over HTTPS; prevents transmission over unencrypted connections.                                         |
| `SameSite`       | `lax`         | Sent only for same-site requests and top-level navigations; mitigates CSRF.                                       |
| `__Host-` prefix | `true` (prod) | Enforces `Secure`, no `Domain` attribute, and root `Path`; provides additional browser-level security guarantees. |

### Session Fixation Prevention

On successful login, a **new session ID** is generated, and the old session is destroyed. This prevents attackers from fixing a known session ID before the user logs in.

### Session Timeouts

Two timeout mechanisms work together:

1. **Idle Timeout** (`SESSION_IDLE_MINUTES`, default: 120 minutes):
   - A rolling timeout that resets on each request.
   - If the user is inactive for longer than the configured period, the session expires.

2. **Absolute Timeout** (`SESSION_ABSOLUTE_DAYS`, default: 30 days):
   - A hard cap on session lifetime regardless of activity.
   - Even active users must re-authenticate after this period.

### "Remember Me" Extended Sessions

When users check "remember me" during login, the session idle timeout is extended to `SESSION_REMEMBER_DAYS` (default: 14 days). Without "remember me," the standard idle timeout applies.

### Immediate Invalidation

On every authenticated request, the user is **reloaded from the database**. This means:

- **Role changes** take effect immediately without waiting for session expiration.
- **Account deletions** immediately invalidate all sessions.
- **Email verification status** changes are reflected immediately.

### Session Cleanup

Expired sessions are cleaned up by `connect-pg-simple` based on the `expire` column. The cleanup is performed automatically by the session store.

---

## Email Verification

### Modes

Email verification can be configured in three modes:

| Mode       | Behavior                                                                |
| ---------- | ----------------------------------------------------------------------- |
| `off`      | No email verification; users can log in immediately after registration. |
| `optional` | Verification email is sent, but users can log in without verifying.     |
| `required` | Users **cannot log in** until they verify their email address.          |

### Token-Based Verification

1. **Token Generation**: A 256-bit random token is generated and its SHA-256 hash is stored in the `auth_tokens` table.
2. **Email Delivery**: The raw token is sent to the user's email address.
3. **Token Consumption**: When the user clicks the verification link, the token is consumed (marked as `used_at`) and cannot be reused.
4. **Atomic Invalidation**: Issuing a new verification token invalidates any previous unexpired tokens.

### URL Fragment Delivery

Verification tokens are delivered in the URL fragment (`/#/verify-email?token=...`) rather than the query string. This prevents:

- The token from being sent to the server in the HTTP request.
- The token from appearing in server access logs.
- The token from leaking via the `Referer` header to external resources.

After processing, the frontend removes the token from the address bar.

### Resend Verification

Users can request a new verification email via `POST /api/auth/resend-verification`. The endpoint:

- Returns the same response whether the email exists or not.
- Does not send an email if the account is already verified or does not exist.
- Is rate-limited per address and per IP.

---

## Password Reset

### Secure Reset Flow

1. **Request**: User submits their email via `POST /api/auth/forgot-password`.
2. **Uniform Response**: The endpoint returns the same message whether the email exists or not.
3. **Token Issuance**: If the account exists, a 256-bit random token is generated and its hash is stored with a 30-minute TTL.
4. **Email Delivery**: The raw token is sent in a password reset link via email.
5. **Token Consumption**: User submits the token and new password via `POST /api/auth/reset-password`.
6. **Atomic Operations**: Within a database transaction:
   - The token is consumed (marked as used).
   - The password hash is updated.
   - The email is marked as verified (proving control of the address).
   - All sessions for the user are deleted (signs out all devices).
7. **Success**: The user can now log in with the new password.

### Security Features

- **Single-Use Tokens**: Tokens are consumed on first use and cannot be reused.
- **TTL Enforcement**: Tokens expire after 30 minutes (`RESET_TOKEN_MINUTES`).
- **Atomic Invalidation**: A new reset token invalidates any previous unexpired tokens.
- **All-Devices Sign-Out**: Password reset automatically signs out all active sessions, preventing unauthorized access from compromised sessions.

---

## Role-Based Access Control (RBAC)

### Built-in Roles

| Role    | Description                                                                         |
| ------- | ----------------------------------------------------------------------------------- |
| `user`  | Default role for registered users. Can access authentication and account endpoints. |
| `admin` | Administrative role. Can access admin endpoints to manage users.                    |

### Role Enforcement

Roles are enforced at the middleware level:

1. **Public Routes**: No authentication required.
2. **Authenticated Routes**: The `authenticate` middleware attaches `req.user` to the request. If no valid session exists, the request is rejected with `401`.
3. **Admin Routes**: After authentication, the role is checked. If `req.user.role !== 'admin'`, the request is rejected with `403`.

### Admin Capabilities

Admins have access to the following endpoints:

- **List Users** (`GET /api/admin/users`): Paginated list of all users with query parameters `page` and `pageSize`.
- **Change User Role** (`PATCH /api/admin/users/:id/role`): Promote or demote users. Admins **cannot change their own role**.

### Self-Protection

The admin role change endpoint explicitly prevents an admin from changing their own role. This prevents accidental or malicious self-demotion that could lock out the last admin.

---

## CSRF Protection

Gatekeeper implements a **three-layer CSRF defense**:

### Layer 1: Synchronizer Token Pattern

- A unique, per-session CSRF token is generated and stored in the session.
- The token is obtained via `GET /api/auth/csrf`.
- Every non-GET/HEAD/OPTIONS request must include the token in the `X-CSRF-Token` header.
- The server validates the submitted token against the session-stored token.

### Layer 2: Origin Header Validation

- For non-simple requests, the `Origin` header is validated against the `APP_URL`.
- Requests without an `Origin` header (e.g., same-origin navigations, non-browser clients) are allowed.
- This provides defense-in-depth even if the CSRF token is leaked.

### Layer 3: JSON-Only Bodies

- Only `application/json` content types are accepted for state-changing requests.
- Browsers do not auto-submit `application/json` in cross-origin forms, making CSRF via form submission impossible.

### Layer 4: SameSite Cookies (Defense-in-Depth)

- `SameSite=Lax` cookies are not sent on cross-origin POST requests, providing an additional (but not sole) layer of protection.

---

## Rate Limiting

Gatekeeper applies rate limiting on multiple dimensions to mitigate brute-force attacks and resource exhaustion.

### Rate Limit Scopes

| Endpoint Category  | Scope                 | Window     | Limit        |
| ------------------ | --------------------- | ---------- | ------------ |
| Global API         | All `/api/*` requests | 15 minutes | 300 requests |
| Login              | Per IP address        | 15 minutes | 20 attempts  |
| Login              | Per email address     | 15 minutes | 10 attempts  |
| Registration       | Per IP address        | 1 hour     | 10 attempts  |
| Password Reset     | Per IP address        | 1 hour     | 5 requests   |
| Email Operations   | Per email address     | 1 hour     | 3 requests   |
| Email Verification | Per IP address        | 1 hour     | 10 requests  |

### Implementation

Rate limiters are implemented using `express-rate-limit` with in-memory stores by default. The rate limiters are applied in the middleware pipeline before authentication, ensuring that even unauthenticated requests are limited.

### Considerations for Horizontal Scaling

For deployments with multiple Node.js instances, the in-memory rate limiters will not share state across instances. Options:

1. Use a shared store like Redis with `rate-limit-redis`.
2. Enforce rate limiting at the reverse proxy level (e.g., Nginx `limit_req_zone`).

---

## Security Headers & CSP

Gatekeeper uses **Helmet** to set security headers on all responses.

### Applied Headers

| Header                      | Value (Production)                    | Purpose                                                                                      |
| --------------------------- | ------------------------------------- | -------------------------------------------------------------------------------------------- |
| `Content-Security-Policy`   | `script-src 'self'`                   | Prevents XSS by restricting script sources. Inline scripts and external scripts are blocked. |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Enforces HTTPS for future requests (HSTS).                                                   |
| `X-Content-Type-Options`    | `nosniff`                             | Prevents MIME-type sniffing.                                                                 |
| `Referrer-Policy`           | `no-referrer`                         | Prevents the `Referer` header from being sent.                                               |
| `X-Frame-Options`           | `DENY`                                | Prevents clickjacking by disallowing framing.                                                |
| `X-XSS-Protection`          | `0`                                   | Disables the legacy XSS auditor (modern CSP is used instead).                                |
| `Permissions-Policy`        | (various disabled)                    | Disables unnecessary browser features.                                                       |

### Cache Control

All API responses include `Cache-Control: no-store, no-cache, must-revalidate, private`. This prevents browsers and intermediate proxies from caching sensitive data.

### CSP and Inline Scripts

The strict CSP (`script-src 'self'`) blocks all inline scripts. The frontend complies by:

- Placing all JavaScript in external `.js` files.
- Avoiding `onclick`, `onload`, and other inline event handlers.
- Using `addEventListener` in external scripts.

---

## Account Enumeration Prevention

Account enumeration occurs when an attacker can determine which email addresses are registered with a service. Gatekeeper prevents this through uniform behavior across multiple vectors.

### Strategies

1. **Identical Error Messages**: Login returns the same error for unknown emails and wrong passwords.
2. **Dummy Hash Verification**: Unknown emails trigger an Argon2 verification against a dummy hash, matching the CPU cost of real verifications.
3. **Uniform Registration Response**: Registration returns the same message for new and existing emails.
4. **Uniform Password Reset Response**: The password reset endpoint returns the same response regardless of email existence.
5. **Delayed Verification Check**: Email verification status is checked only after password verification, preventing enumeration via login timing.
6. **Uniform Rate Limiting**: Rate limit behavior is identical for existing and non-existing accounts.

---

## Token Security

### Generation

Tokens are generated using `crypto.randomBytes(32)`, producing 256 bits (32 bytes) of cryptographically secure randomness. The raw token is 43 characters when base64url-encoded.

### Storage

Only the **SHA-256 hash** (64 hex characters) of the token is stored in the `auth_tokens` table. The raw token is:

- Sent to the user via email.
- Never persisted in the database.
- Never logged.

This ensures that even if the database is compromised, the raw tokens cannot be recovered.

### Single-Use Enforcement

Tokens are consumed (marked with `used_at`) on first use. Subsequent attempts to use the same token are rejected.

### Atomic Invalidation

When a new token is issued for a user and purpose, any previous unexpired tokens for the same user and purpose are replaced. This ensures that only the most recent token is valid.

### URL Fragment Delivery

Tokens are delivered in the URL fragment (`/#/verify-email?token=...` or `/#/reset-password?token=...`) rather than the query string. This prevents:

- **Server Logs**: The fragment is not sent to the server, so it does not appear in access logs.
- **Referer Leakage**: The fragment is not included in the `Referer` header when the user navigates to external sites.
- **Browser History**: While fragments are stored in browser history, they are not sent over the network.

After processing the token, the frontend removes it from the address bar using `history.replaceState`.

---

## Database-Backed Sessions

### Why PostgreSQL?

Storing sessions in PostgreSQL (via `connect-pg-simple`) provides:

- **Persistence**: Sessions survive server restarts.
- **Scalability**: Multiple server instances can share the same session store, enabling horizontal scaling.
- **Security**: Session data is stored server-side; the client holds only a signed session ID.
- **Observability**: Sessions can be inspected and managed via SQL queries.

### Session Data

The `session` table stores serialized session JSON in the `sess` column. This includes:

- Session metadata (creation time, expiration).
- User ID (`userId`) attached during authentication.
- CSRF token.
- Any other session-specific data.

### Connection Pooling

Gatekeeper uses a PostgreSQL connection pool (`src/db/pool.js`) to manage database connections efficiently. The pool size is configurable via `DATABASE_POOL_MAX` (default: 10).

### Transaction Support

Critical operations (password reset, email verification) use database transactions (`withTransaction`) to ensure atomicity. If any step fails, the entire operation is rolled back.

---

## Frontend Features

### Single-Page Application (SPA)

The frontend is a lightweight SPA that runs entirely in the browser. It communicates with the backend via a JSON API.

### Views

The application includes the following views:

- **Login**: Email and password login form with "remember me" option.
- **Register**: Name, email, and password registration form.
- **Forgot Password**: Email input for requesting a password reset.
- **Reset Password**: New password form (accessed via token from email).
- **Verify Email**: Email verification confirmation (accessed via token from email).
- **Account**: Profile view where users can update their name.
- **Admin**: User management interface for administrators.

### API Client

The `public/js/api.js` module provides a Fetch API wrapper with:

- **CSRF Token Injection**: Automatically reads the `X-CSRF-Token` cookie and includes it in the `X-CSRF-Token` header for non-GET requests.
- **Token Cleanup**: Removes the `token` query parameter from the URL after processing to prevent leakage.
- **Error Handling**: Parses error responses and throws descriptive errors.
- **Authentication Redirect**: Redirects to the login page on `401` responses.

### Client-Side Validation

The `public/js/validators.js` module provides real-time validation for:

- **Name**: Length and character restrictions.
- **Email**: Format validation.
- **Password**: Minimum length (10 characters).
- **Password Confirmation**: Matching confirmation field.

Validation messages are displayed inline as the user types.

### Responsive Design

The CSS (`public/css/styles.css`) provides a responsive layout that works on desktop and mobile devices.

---

## Configuration & Validation

### Centralized Configuration

All configuration is managed through `src/config/index.js`, which reads environment variables, applies defaults, and performs validation.

### Fail-Fast Startup

The application validates all configuration at startup and exits with a descriptive error if any rule is violated. This prevents running with unsafe or incomplete configuration.

### Validation Rules

| Rule                                            | Condition  | Action                                  |
| ----------------------------------------------- | ---------- | --------------------------------------- |
| `SESSION_SECRET` missing or < 32 chars          | At startup | Exit with error                         |
| `APP_URL` not HTTPS in production               | At startup | Exit with error                         |
| `COOKIE_SECURE` not `true` in production        | At startup | Exit with error                         |
| `ARGON2_MEMORY_KIB` < 19456 in production       | At startup | Exit with error                         |
| `ARGON2_TIME_COST` < 2 in production            | At startup | Exit with error                         |
| `EMAIL_TRANSPORT` not `smtp` in production      | At startup | Exit with error                         |
| `SMTP_HOST` missing when `EMAIL_TRANSPORT=smtp` | At startup | Exit with error                         |
| `TRUST_PROXY=true`                              | At startup | Exit with error (use numeric hop count) |

### Environment Modes

| Mode        | `NODE_ENV`    | Behavior                                                                 |
| ----------- | ------------- | ------------------------------------------------------------------------ |
| Development | `development` | Console email transport, verbose errors, no HTTPS enforcement.           |
| Test        | `test`        | In-memory email transport, rate limiting disabled, test database.        |
| Production  | `production`  | SMTP required, HTTPS enforced, strict Argon2 parameters, secure cookies. |

---

## Observability & Operations

### Graceful Shutdown

Gatekeeper handles `SIGTERM` and `SIGINT` signals gracefully:

1. Stops accepting new connections.
2. Closes the database connection pool.
3. Exits with code 0.

This ensures in-flight requests complete and database connections are cleanly released.

### Startup Health Check

On startup, Gatekeeper executes a `SELECT 1` query against PostgreSQL to verify database connectivity. If the database is unreachable, the process exits with an error.

### Logging

- **Startup**: Server listening message with port, environment, and app URL.
- **Database Errors**: Connection failures are logged to `stderr`.
- **Password Rehash Failures**: Logged as errors but do not crash the process.
- **Unhandled Rejections**: Logged to `stderr`.

### CLI Tools

- **`npm run db:migrate`**: Runs database migrations.
- **`npm run db:migrate:test`**: Runs migrations against the test database.
- **`npm run create-admin`**: Creates an admin user interactively.

---

## Feature Comparison Matrix

| Feature                        | Gatekeeper                         | Typical DIY Auth             | Passport.js (Local Strategy) |
| ------------------------------ | ---------------------------------- | ---------------------------- | ---------------------------- |
| Password Hashing               | ✅ Argon2id (auto-rehash)          | ⚠️ Depends on implementation | ⚠️ Depends on implementation |
| Session Storage                | ✅ PostgreSQL                      | ⚠️ Depends on implementation | ⚠️ Memory by default         |
| CSRF Protection                | ✅ Built-in                        | ❌ Must implement            | ❌ Must implement            |
| Rate Limiting                  | ✅ Multi-layered                   | ❌ Must implement            | ❌ Must implement            |
| Account Enumeration Prevention | ✅ Built-in                        | ❌ Easy to forget            | ❌ Easy to forget            |
| Email Verification             | ✅ Built-in                        | ❌ Must implement            | ❌ Must implement            |
| Password Reset                 | ✅ Built-in                        | ❌ Must implement            | ❌ Must implement            |
| Token Security                 | ✅ Hash-only storage, URL fragment | ❌ Must implement            | ❌ Must implement            |
| RBAC                           | ✅ User/Admin roles                | ❌ Must implement            | ⚠️ Basic role support        |
| Security Headers               | ✅ Helmet (CSP, HSTS)              | ❌ Must implement            | ❌ Must implement            |
| Input Validation               | ✅ Server-side + client-side       | ❌ Must implement            | ❌ Must implement            |
| XSS Prevention                 | ✅ CSP, no innerHTML               | ❌ Must implement            | ❌ Not applicable            |
| SQL Injection Prevention       | ✅ Parameterized queries           | ⚠️ Depends on implementation | ⚠️ Depends on implementation |
| Frontend                       | ✅ Included (vanilla JS)           | ❌ Must build                | ❌ Must build                |
| Configuration Validation       | ✅ Fail-fast at startup            | ❌ Must implement            | ❌ Not applicable            |
| Horizontal Scaling             | ✅ (with shared rate limiter)      | ⚠️ Depends on implementation | ⚠️ Depends on implementation |
| Documentation                  | ✅ Comprehensive                   | ⚠️ Varies                    | ⚠️ Varies                    |

**Legend**: ✅ Built-in and enabled by default | ⚠️ Available but requires manual configuration | ❌ Not included

---

## Summary

Gatekeeper provides a **complete, production-ready authentication system** with defense-in-depth security. It is designed to be:

- **Secure by default**: Every common web vulnerability is addressed out of the box.
- **Easy to deploy**: Minimal configuration, comprehensive documentation, and fail-fast validation.
- **Maintainable**: Clean separation of concerns, clear code structure, and extensive test coverage.
- **Flexible**: Configurable via environment variables to adapt to different deployment scenarios.

Whether you are building a small application or a large-scale platform, Gatekeeper gives you a solid, auditable authentication foundation that you can trust.
