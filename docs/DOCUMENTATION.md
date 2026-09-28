# Gatekeeper Documentation

## Table of Contents

1. [Product Overview](#product-overview)
2. [Core Principles](#core-principles)
3. [System Architecture](#system-architecture)
4. [Directory Structure](#directory-structure)
5. [Technology Stack](#technology-stack)
6. [Getting Started](#getting-started)
7. [Configuration Reference](#configuration-reference)
8. [Database Schema](#database-schema)
9. [Security Model](#security-model)
10. [Middleware Pipeline](#middleware-pipeline)
11. [API Reference](#api-reference)
12. [Authentication Flows](#authentication-flows)
13. [Role-Based Access Control](#role-based-access-control)
14. [Error Handling](#error-handling)
15. [Frontend Architecture](#frontend-architecture)
16. [Testing](#testing)
17. [Production Deployment](#production-deployment)
18. [Maintenance & Operations](#maintenance--operations)
19. [Known Trade-offs & Roadmap](#known-trade-offs--roadmap)
20. [FAQ & Troubleshooting](#faq--troubleshooting)

---

## Product Overview

**Gatekeeper** is a production-grade, session-based authentication and authorization system built for modern web applications. It provides a complete, secure authentication layer out of the box — from user registration and email verification to password reset, session management, and administrative user oversight.

### What Gatekeeper Provides

- **User Lifecycle Management**: Registration, login, logout, profile updates, and email verification.
- **Secure Password Handling**: Passwords are hashed using **Argon2id**, the winner of the Password Hashing Competition (PHC), with automatic rehashing when parameters are strengthened.
- **Session Management**: Server-side sessions stored in **PostgreSQL** using `connect-pg-simple`. Sessions are protected against fixation, hijacking, and brute-force attacks.
- **Email Verification & Password Reset**: Secure, single-use tokens for email verification and password recovery, with configurable token lifetimes.
- **Role-Based Access Control (RBAC)**: Built-in `user` and `admin` roles with middleware-enforced route protection.
- **Rate Limiting**: Comprehensive rate-limiting on all sensitive endpoints (login, registration, password reset, email operations) to mitigate brute-force attacks.
- **CSRF Protection**: Per-session synchronizer tokens on every state-changing request, backed by an Origin allow-list check.
- **Security Hardened Out of the Box**: Helmet security headers, Content Security Policy (CSP), HSTS (in production), `Secure`/`HttpOnly`/`SameSite` cookies, `__Host-` cookie prefix in production, and strict input validation.

### Who Should Use Gatekeeper

- Developers building **Node.js/Express** applications who need a robust, battle-tested authentication layer without reinventing the wheel.
- Teams that prioritize **security** and want defense-in-depth (OWASP-aligned protections) without deep security expertise.
- Projects that prefer **vanilla JavaScript frontends** and want to avoid heavy frontend framework dependencies for the auth layer.
- Applications that require **PostgreSQL-backed sessions** for scalability and horizontal compatibility.

---

## Core Principles

### 1. Security First

Every design decision in Gatekeeper is evaluated through a security lens. This means:

- **Defense in Depth**: Multiple overlapping controls (CSRF tokens + Origin checks + SameSite cookies + CSP) rather than relying on a single mechanism.
- **Fail Secure**: On misconfiguration or unexpected input, the system defaults to denying access rather than granting it.
- **Minimal Information Leakage**: Identical error messages and response times for valid and invalid inputs to prevent account enumeration.

### 2. Transparency & Auditability

- All SQL queries use **parameterized statements** — no string concatenation.
- Error responses to clients contain **no stack traces**.
- Configuration is centralized and validated at startup — the app **refuses to start** if settings are unsafe or missing.

### 3. Simplicity & Predictability

- Plain, dependency-free vanilla JavaScript for the frontend auth UI.
- Clear separation of concerns: routes wire middleware to controllers; controllers handle HTTP; services contain business logic; the database layer handles all SQL.
- A small, focused dependency tree to minimize supply-chain risk.

### 4. Standards Compliance

- Follows **NIST SP 800-63B** digital identity guidelines for password policies (length-first, no composition rules).
- Uses **OWASP-recommended** Argon2id parameters (minimum 19 MiB memory, 2 passes).
- Session cookie attributes follow browser security best practices (`Secure`, `HttpOnly`, `SameSite`, `__Host-` prefix).

---

## System Architecture

Gatekeeper follows a layered architecture pattern:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client (Browser)                         │
│         Vanilla JS / Fetch API / JSON bodies                     │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTPS
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Express Application                         │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Middleware Pipeline (ordered)                            │  │
│  │  1. Security Headers (Helmet)                             │  │
│  │  2. Static File Serving                                   │  │
│  │  3. No-Store Cache Control                                │  │
│  │  4. CORS                                                  │  │
│  │  5. Origin Check                                          │  │
│  │  6. Rate Limiting (global + per-endpoint)                 │  │
│  │  7. Require JSON                                          │  │
│  │  8. JSON Body Parsing (10kb limit)                        │  │
│  │  9. Session Middleware (PostgreSQL-backed)                │  │
│  │ 10. Authentication Middleware                             │  │
│  │ 11. CSRF Protection                                       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                            │                                    │
│  ┌─────────────────────────▼────────────────────────────────┐  │
│  │  API Router                                              │  │
│  │   /api/auth/*        → Auth controller                    │  │
│  │   /api/account       → Account controller                 │  │
│  │   /api/admin/*       → Admin controller                   │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Service Layer                                │
│   auth.service.js  │  password.js  │  tokens.js  │  email.js    │
│   (business logic, no HTTP concerns)                            │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Database Layer                               │
│   pool.js  │  users.js  │  tokens.js  │  schema.sql           │
│   (parameterized SQL, transactions, connection pooling)         │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                     PostgreSQL                                  │
│   users │ auth_tokens │ session (connect-pg-simple)             │
└─────────────────────────────────────────────────────────────────┘
```

### Request Lifecycle

1. **Request arrives** at Express.
2. **Security headers** are applied (Helmet).
3. **Static assets** are served if the request matches a public file.
4. For `/api/*` requests:
   - `Cache-Control: no-store` is enforced.
   - **CORS** headers are set; non-allowlisted origins are rejected.
   - **Origin** header is validated against `APP_URL`.
   - **Rate limiters** are checked.
   - The request body is validated as JSON and parsed (max 10 KB).
   - **Session middleware** loads or creates a PostgreSQL session.
   - **Authentication middleware** attaches the current user to `req.user`.
   - **CSRF protection** validates the `X-CSRF-Token` header for non-GET requests.
   - The **route handler** executes business logic.
5. The response is returned; any errors are formatted by the centralized error handler.

---

## Directory Structure

```
gatekeeper/
├── db/
│   └── schema.sql                 # Idempotent PostgreSQL schema (users, auth_tokens, session)
├── scripts/
│   ├── migrate.js                 # Database migration runner
│   └── create-admin.js            # CLI to create an admin user
├── src/
│   ├── server.js                  # Entry point; DB connectivity check; graceful shutdown
│   ├── app.js                     # Express app factory; middleware ordering
│   ├── config/
│   │   └── index.js               # Validated environment configuration (fails fast)
│   ├── routes/
│   │   ├── index.js               # API router assembly
│   │   ├── auth.routes.js         # Authentication routes (register, login, etc.)
│   │   ├── account.routes.js      # Account management routes
│   │   └── admin.routes.js        # Admin-only routes
│   ├── controllers/
│   │   └── (HTTP concerns: status codes, sessions, cookies)
│   ├── services/
│   │   ├── auth.service.js        # Core auth logic (register, login, reset, verify)
│   │   ├── password.js            # Argon2id hashing, verification, rehash detection
│   │   ├── tokens.js              # Secure token generation, hashing, consumption
│   │   └── email.js               # Email sending (SMTP or console transport)
│   ├── db/
│   │   ├── pool.js                # PostgreSQL connection pool
│   │   ├── users.js               # User-related SQL queries
│   │   └── tokens.js              # Token-related SQL queries
│   ├── middleware/
│   │   ├── session.js             # express-session + connect-pg-simple setup
│   │   ├── security.js            # Helmet headers, CORS, no-store
│   │   ├── csrf.js                # Synchronizer token + Origin check
│   │   ├── authenticate.js        # Attaches req.user from session
│   │   ├── rateLimit.js           # Express rate limiter instances
│   │   ├── requireJson.js         # Rejects non-JSON bodies
│   │   └── errorHandler.js        # Centralized error formatting
│   └── validators/
│       └── index.js               # Server-side validation and sanitization
├── public/
│   ├── index.html                 # Single-page application shell
│   ├── css/
│   │   └── styles.css             # Application styles
│   └── js/
│       ├── api.js                 # Fetch wrapper with CSRF token handling
│       ├── app.js                 # UI logic, routing, form handling
│       └── validators.js          # Client-side form validation
├── tests/                         # Node:test + Supertest integration tests
├── package.json
├── .env.example                   # Environment variable template
└── README.md
```

---

## Technology Stack

### Backend

| Component        | Technology            | Purpose                                          |
| ---------------- | --------------------- | ------------------------------------------------ |
| Runtime          | Node.js 20+           | Server-side JavaScript execution                 |
| Framework        | Express 5             | HTTP server, routing, middleware                 |
| Database         | PostgreSQL 13+        | Persistent storage for users, tokens, sessions   |
| Password Hashing | Argon2id (argon2 npm) | Secure password hashing (OWASP-recommended)      |
| Session Store    | connect-pg-simple     | PostgreSQL-backed session storage                |
| Email            | Nodemailer            | Transactional emails (SMTP or console transport) |
| Security Headers | Helmet                | CSP, HSTS, X-Frame-Options, etc.                 |
| CSRF Protection  | Custom middleware     | Synchronizer token + Origin validation           |
| Rate Limiting    | express-rate-limit    | Brute-force mitigation                           |
| Validation       | Custom validators     | Server-side input validation and sanitization    |
| Testing          | Node:test + Supertest | Integration tests against a real database        |

### Frontend

| Component  | Technology                      | Purpose                                   |
| ---------- | ------------------------------- | ----------------------------------------- |
| Markup     | HTML5                           | Single-page application structure         |
| Styling    | CSS3                            | Responsive, accessible styling            |
| Scripting  | Vanilla JavaScript (ES Modules) | No framework dependencies                 |
| API Client | Fetch API                       | JSON-based communication with the backend |

---

## Getting Started

### Prerequisites

- **Node.js** 20 or later
- **PostgreSQL** 13 or later
- A **terminal** with Bash, Zsh, or PowerShell

### Installation Steps

#### 1. Clone or Download the Project

Ensure you have the Gatekeeper source code on your local machine.

#### 2. Install Dependencies

```bash
npm install
```

This installs all required runtime and development dependencies.

#### 3. Create the Databases

Connect to PostgreSQL as a superuser (e.g., via `psql`) and run:

```sql
CREATE USER gatekeeper WITH PASSWORD 'change_me';
CREATE DATABASE gatekeeper OWNER gatekeeper;
CREATE DATABASE gatekeeper_test OWNER gatekeeper;
```

> **Note**: Replace `'change_me'` with a strong password. In production, use a least-privilege database user with no superuser or DDL rights at runtime if migrations are run separately.

#### 4. Configure Environment Variables

Copy the example environment file:

```bash
cp .env.example .env
```

Generate a secure session secret:

```bash
node -p "require('crypto').randomBytes(48).toString('base64url')"
```

Paste the output into the `.env` file as the value for `SESSION_SECRET`.

Edit `.env` and set at least:

- `DATABASE_URL=postgresql://gatekeeper:change_me@localhost:5432/gatekeeper`
- `TEST_DATABASE_URL=postgresql://gatekeeper:change_me@localhost:5432/gatekeeper_test`
- `SESSION_SECRET=<your-generated-secret>`
- `APP_URL=http://localhost:3000`

#### 5. Run Database Migrations

```bash
npm run db:migrate
```

This creates the `users`, `auth_tokens`, and `session` tables.

#### 6. Create an Admin User

```bash
npm run create-admin -- you@example.com "Your Name"
```

You will be prompted to enter a password for the admin account.

#### 7. Start the Development Server

```bash
npm run dev
```

The application is now running at `http://localhost:3000`.

### Verify the Installation

1. Open `http://localhost:3000` in your browser.
2. Register a new account.
3. Check the terminal for the verification email (in development, emails are printed to the console).
4. Log in with your new account.

---

## Configuration Reference

Gatekeeper is configured exclusively through **environment variables**. The application performs **fail-fast validation** at startup and will refuse to start if any required variable is missing or if a value is unsafe.

### Environment Variables

| Variable                 | Default                           | Description                                                                                                                          |
| ------------------------ | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `NODE_ENV`               | `development`                     | Environment mode. `production` enforces stricter rules (HTTPS, Argon2 minimums, SMTP required).                                      |
| `PORT`                   | `3000`                            | Port the server listens on.                                                                                                          |
| `APP_URL`                | `http://localhost:3000`           | Public origin URL. **Must use `https` in production.** Used for email links and Origin validation.                                   |
| `DATABASE_URL`           | (required)                        | PostgreSQL connection string for the application database.                                                                           |
| `TEST_DATABASE_URL`      | —                                 | PostgreSQL connection string for the test database. Name must contain `test`.                                                        |
| `DATABASE_SSL`           | `false`                           | Set to `true` to enable TLS for database connections (required for remote databases in production).                                  |
| `DATABASE_POOL_MAX`      | `10`                              | Maximum number of connections in the PostgreSQL pool.                                                                                |
| `SESSION_SECRET`         | (required)                        | Comma-separated list of secrets for signing session cookies. **Minimum 32 characters each.** Supports key rotation (newest first).   |
| `SESSION_IDLE_MINUTES`   | `120`                             | Idle session timeout in minutes (rolling — resets on activity).                                                                      |
| `SESSION_REMEMBER_DAYS`  | `14`                              | Session lifetime when "keep me signed in" is enabled.                                                                                |
| `SESSION_ABSOLUTE_DAYS`  | `30`                              | Hard maximum session lifetime, regardless of activity.                                                                               |
| `COOKIE_SECURE`          | `true` in production              | `Secure` flag on cookies. **Must be `true` in production.** Enables the `__Host-` cookie prefix.                                     |
| `COOKIE_SAMESITE`        | `lax`                             | `SameSite` attribute. Options: `lax`, `strict`.                                                                                      |
| `TRUST_PROXY`            | `0`                               | Number of reverse-proxy hops. Required for correct IPs and `Secure` cookies behind a proxy (e.g., `1` for a single load balancer).   |
| `CORS_ORIGINS`           | (empty)                           | Comma-separated list of allowed browser origins for credentialed requests. Empty = same-origin only.                                 |
| `ARGON2_MEMORY_KIB`      | `19456`                           | Argon2id memory cost in KiB. OWASP minimum is 19456 (19 MiB).                                                                        |
| `ARGON2_TIME_COST`       | `2`                               | Argon2id time cost (passes). OWASP minimum is 2.                                                                                     |
| `EMAIL_VERIFICATION`     | `optional`                        | Email verification mode: `off` (no verification), `optional` (email sent, login allowed), `required` (login blocked until verified). |
| `RESET_TOKEN_MINUTES`    | `30`                              | Password reset token lifetime in minutes.                                                                                            |
| `VERIFY_TOKEN_HOURS`     | `24`                              | Email verification token lifetime in hours.                                                                                          |
| `EMAIL_TRANSPORT`        | `console` (dev) / `smtp` (prod)   | Email transport: `console` (prints to terminal) or `smtp`. **Must be `smtp` in production.**                                         |
| `SMTP_HOST`              | —                                 | SMTP server hostname (required when `EMAIL_TRANSPORT=smtp`).                                                                         |
| `SMTP_PORT`              | `587`                             | SMTP server port.                                                                                                                    |
| `SMTP_SECURE`            | `false`                           | Use TLS for SMTP connection.                                                                                                         |
| `SMTP_USER`              | —                                 | SMTP authentication username.                                                                                                        |
| `SMTP_PASS`              | —                                 | SMTP authentication password.                                                                                                        |
| `EMAIL_FROM`             | `Gatekeeper <no-reply@localhost>` | Sender address for outgoing emails.                                                                                                  |
| `RATE_LIMIT_ENABLED`     | `true` (disabled in test)         | Enable or disable rate limiting globally.                                                                                            |
| `RL_GLOBAL_LIMIT`        | `300`                             | Global API rate limit (requests per 15 minutes).                                                                                     |
| `RL_LOGIN_IP_LIMIT`      | `20`                              | Login attempts per IP per 15 minutes.                                                                                                |
| `RL_LOGIN_ACCOUNT_LIMIT` | `10`                              | Login attempts per email address per 15 minutes.                                                                                     |
| `RL_REGISTER_LIMIT`      | `10`                              | Registration attempts per IP per hour.                                                                                               |
| `RL_RESET_LIMIT`         | `5`                               | Password reset requests per IP per hour.                                                                                             |
| `RL_EMAIL_ACCOUNT_LIMIT` | `3`                               | Email-related requests per address per hour.                                                                                         |
| `RL_VERIFY_LIMIT`        | `10`                              | Email verification attempts per IP per hour.                                                                                         |

### Startup Validation Rules

The application performs the following checks at startup and exits with an error if any rule is violated:

1. `SESSION_SECRET` must be present and all entries must be ≥ 32 characters.
2. `APP_URL` must be a valid URL; in production, it must use `https`.
3. `COOKIE_SECURE` must be `true` in production.
4. `ARGON2_MEMORY_KIB` must be ≥ 19456 and `ARGON2_TIME_COST` must be ≥ 2 in production.
5. `EMAIL_TRANSPORT` must be `smtp` in production.
6. `SMTP_HOST` must be set when `EMAIL_TRANSPORT=smtp`.
7. `TRUST_PROXY` cannot be `true` (use a numeric hop count instead).

---

## Database Schema

### Overview

Gatekeeper uses three PostgreSQL tables:

| Table         | Purpose                                                            |
| ------------- | ------------------------------------------------------------------ |
| `users`       | Stores user accounts, credentials, roles, and verification status. |
| `auth_tokens` | Stores password reset and email verification tokens.               |
| `session`     | Stores server-side sessions (managed by `connect-pg-simple`).      |

### users Table

| Column              | Type          | Constraints                                                       | Description                        |
| ------------------- | ------------- | ----------------------------------------------------------------- | ---------------------------------- |
| `id`                | `uuid`        | `PRIMARY KEY`, `DEFAULT gen_random_uuid()`                        | Unique user identifier.            |
| `name`              | `text`        | `NOT NULL`                                                        | Display name.                      |
| `email`             | `text`        | `NOT NULL`, `UNIQUE`, `CHECK (email = lower(email))`              | Email address (stored lowercase).  |
| `password_hash`     | `text`        | `NOT NULL`                                                        | Argon2id password hash.            |
| `role`              | `text`        | `NOT NULL`, `CHECK (role IN ('user', 'admin'))`, `DEFAULT 'user'` | User role for RBAC.                |
| `email_verified_at` | `timestamptz` | —                                                                 | Timestamp when email was verified. |
| `created_at`        | `timestamptz` | `NOT NULL`, `DEFAULT now()`                                       | Account creation timestamp.        |
| `updated_at`        | `timestamptz` | `NOT NULL`, `DEFAULT now()`                                       | Last update timestamp.             |

### auth_tokens Table

| Column       | Type          | Constraints                                             | Description                                        |
| ------------ | ------------- | ------------------------------------------------------- | -------------------------------------------------- |
| `id`         | `uuid`        | `PRIMARY KEY`, `DEFAULT gen_random_uuid()`              | Unique token identifier.                           |
| `user_id`    | `uuid`        | `NOT NULL`, `FK → users(id) ON DELETE CASCADE`          | Owner of the token.                                |
| `purpose`    | `text`        | `NOT NULL`                                              | Token purpose: `email_verify` or `password_reset`. |
| `token_hash` | `text`        | `NOT NULL`, `UNIQUE`, `CHECK (length(token_hash) = 64)` | SHA-256 hash of the token (64 hex chars).          |
| `expires_at` | `timestamptz` | `NOT NULL`                                              | Token expiration timestamp.                        |
| `used_at`    | `timestamptz` | —                                                       | Timestamp when the token was consumed.             |
| `created_at` | `timestamptz` | `NOT NULL`, `DEFAULT now()`                             | Token creation timestamp.                          |

> **Security Note**: Only the SHA-256 hash of the token is stored in the database. The raw token is sent to the user via email and is never persisted.

### session Table

| Column   | Type          | Constraints   | Description                                               |
| -------- | ------------- | ------------- | --------------------------------------------------------- |
| `sid`    | `text`        | `PRIMARY KEY` | Session ID (signed random string).                        |
| `sess`   | `json`        | `NOT NULL`    | Serialized session data (managed by `connect-pg-simple`). |
| `expire` | `timestamptz` | `NOT NULL`    | Session expiration timestamp.                             |

> **Performance Note**: For high-volume deployments with many concurrent sessions, consider adding an index on `(sess->>'userId')` after converting the `sess` column to `jsonb` for faster session invalidation on password reset.

### Schema Management

The schema is managed via an idempotent SQL script (`db/schema.sql`) executed by `scripts/migrate.js`. The script uses `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS` to be safely re-runnable.

---

## Security Model

Gatekeeper implements defense-in-depth security across multiple layers.

### Password Security

- **Algorithm**: **Argon2id** (a hybrid of Argon2i and Argon2d), the current state-of-the-art for password hashing.
- **Default Parameters**: 19 MiB memory, 2 passes, 1 lane (parallelism).
- **Policy**: Length-first (10–128 characters), no composition rules (NIST 800-63B compliant), with a blocklist of common passwords.
- **Automatic Rehashing**: When a user logs in with a password hashed using weaker parameters, the hash is transparently upgraded to the current configuration.
- **Timing Attack Mitigation**: A dummy hash is verified for unknown emails to ensure identical response times regardless of account existence.

### Session Security

- **Storage**: Server-side in PostgreSQL. The cookie contains only a signed, random session ID — no sensitive data.
- **Cookie Flags**:
  - `HttpOnly`: Prevents JavaScript access to the session cookie (mitigates XSS).
  - `Secure`: Transmitted only over HTTPS (enforced in production).
  - `SameSite=Lax`: Sent only for same-site requests and top-level navigations.
  - `__Host-` prefix: In production, the cookie uses the `__Host-` prefix, which enforces `Secure`, no `Domain` attribute, and root `Path`.
- **Session Fixation Prevention**: A new session ID is issued at login; the old session is destroyed.
- **Session Termination**: Sessions are destroyed on explicit logout and on password reset (all devices are signed out).
- **Timeouts**:
  - **Idle timeout**: Rolling timeout that resets on each request.
  - **Absolute timeout**: Hard cap on session lifetime regardless of activity.
- **Immediate Invalidation**: The user record is reloaded from the database on every authenticated request. Role changes, account deletions, and email verification status changes take effect immediately without waiting for session expiration.

### CSRF Protection

Every non-GET request requires a valid CSRF token, validated through three mechanisms:

1. **Synchronizer Token**: A per-session token obtained via `GET /api/auth/csrf` and submitted in the `X-CSRF-Token` header.
2. **Origin Validation**: The request's `Origin` header must match the `APP_URL`.
3. **JSON-Only Bodies**: Only `application/json` content types are accepted, which browsers do not auto-submit in cross-origin forms.

`SameSite=Lax` cookies provide an additional layer but are not relied upon exclusively.

### XSS Prevention

- **Content Security Policy (CSP)**: Strict `script-src 'self'` policy prevents inline scripts and external script injection. `style-src` restrictions prevent inline styles.
- **No innerHTML**: The frontend exclusively uses `textContent` and text node APIs, never `innerHTML` or `insertAdjacentHTML` with untrusted input.
- **Input Sanitization**: User-provided names are validated against an allow-list regex.

### SQL Injection Prevention

Every database query uses **parameterized statements** (prepared statements). User input is never concatenated or interpolated into SQL strings.

### Account Enumeration Prevention

Gatekeeper prevents attackers from discovering which email addresses are registered:

- **Identical Login Errors**: Unknown emails and wrong passwords return the exact same error message.
- **Dummy Hash Verification**: For unknown emails, a CPU-intensive Argon2 verification is performed against a pre-computed dummy hash to match the timing of real verifications.
- **Uniform Registration Response**: Registration returns the same success message whether the email is new or existing.
- **Uniform Password Reset Response**: The password reset endpoint returns the same response whether the email exists or not.
- **Delayed Verification Check**: Email verification status is checked only after the password is verified, preventing enumeration via the login endpoint.
- **Uniform Rate Limiting**: Rate limit behavior is identical for existing and non-existing accounts.

### Brute Force Mitigation

Rate limits are applied on multiple dimensions:

| Endpoint Category                | Limit Scope | Window     | Limit        |
| -------------------------------- | ----------- | ---------- | ------------ |
| Login                            | Per IP      | 15 minutes | 20 attempts  |
| Login                            | Per email   | 15 minutes | 10 attempts  |
| Registration                     | Per IP      | 1 hour     | 10 attempts  |
| Password Reset                   | Per IP      | 1 hour     | 5 attempts   |
| Email operations (verify/resend) | Per address | 1 hour     | 3 attempts   |
| Email verification               | Per IP      | 1 hour     | 10 attempts  |
| Global API                       | All clients | 15 minutes | 300 requests |

### Token Security

- **Generation**: 256-bit (32-byte) random tokens using `crypto.randomBytes()`.
- **Storage**: Only the SHA-256 hash (64 hex characters) is stored in the database. The raw token is sent to the user and never persisted.
- **Single Use**: Tokens are consumed (marked as `used_at`) on first use and cannot be reused.
- **Atomic Invalidation**: Issuing a new token replaces the previous one for the same user and purpose, invalidating any outstanding tokens.
- **URL Fragment Delivery**: Tokens are delivered in the URL fragment (`/#/reset-password?token=...`) rather than the query string. This prevents the token from being:
  - Sent to the server in the HTTP request.
  - Appearing in server access logs.
  - Leaked via the `Referer` header to external resources.

### Transport & Headers

- **Helmet**: Sets security headers including:
  - `Content-Security-Policy`: `script-src 'self'` (prevents XSS).
  - `Strict-Transport-Security` (HSTS): Enforced in production.
  - `X-Content-Type-Options: nosniff`: Prevents MIME-type sniffing.
  - `Referrer-Policy: no-referrer`: Prevents Referer header leakage.
  - `X-Frame-Options: DENY`: Prevents clickjacking.
- **Cache Control**: `Cache-Control: no-store` on all API responses.
- **CORS**: Allow-list based; credentials are supported but origins must be explicitly configured. Empty by default (same-origin only).
- **Body Size Limit**: JSON payloads are limited to 10 KB.

### Secrets Management

- Configuration is loaded **only from environment variables**. No secrets are hardcoded.
- `.env` files are git-ignored.
- Startup validation rejects weak or missing secrets.
- Error responses to clients never include stack traces or internal implementation details.

---

## Middleware Pipeline

The middleware stack in `src/app.js` is ordered for optimal security and performance. Understanding this order is critical for maintaining security guarantees.

### Middleware Execution Order (for `/api/*`)

```
┌──────────────────────────────────────────────────────────────────────┐
│ 1. noStore                → Cache-Control: no-store                 │
├──────────────────────────────────────────────────────────────────────┤
│ 2. corsMiddleware()       → CORS headers                            │
├──────────────────────────────────────────────────────────────────────┤
│ 3. originCheck()          → Origin header validation                │
├──────────────────────────────────────────────────────────────────────┤
│ 4. limiters.global        → Global rate limit                       │
├──────────────────────────────────────────────────────────────────────┤
│ 5. requireJson            → Rejects non-JSON content types          │
├──────────────────────────────────────────────────────────────────────┤
│ 6. express.json(10kb)     → Parses JSON body (strict mode)          │
├──────────────────────────────────────────────────────────────────────┤
│ 7. createSessionMiddleware() → Loads/creates PostgreSQL session     │
├──────────────────────────────────────────────────────────────────────┤
│ 8. authenticate           → Attaches req.user from session          │
├──────────────────────────────────────────────────────────────────────┤
│ 9. csrfProtection         → Validates X-CSRF-Token header           │
├──────────────────────────────────────────────────────────────────────┤
│ 10. apiRouter(limiters)   → Route-specific rate limits + handlers   │
└──────────────────────────────────────────────────────────────────────┘
```

### Key Middleware Details

#### noStore (`src/middleware/security.js`)

Sets `Cache-Control: no-store, no-cache, must-revalidate, private` on all API responses. Prevents caching of sensitive data by browsers and intermediate proxies.

#### corsMiddleware (`src/middleware/security.js`)

Handles CORS preflight (`OPTIONS`) requests and sets `Access-Control-Allow-Origin` based on the `CORS_ORIGINS` configuration. Credentials are supported, but the origin must be explicitly allow-listed.

#### originCheck (`src/middleware/csrf.js`)

Validates the `Origin` header of incoming requests against the `APP_URL`. Requests without an `Origin` header (e.g., same-origin navigations, non-browser clients) are allowed to proceed, as they cannot be forged cross-origin.

#### limiters.global (`src/middleware/rateLimit.js`)

A global rate limiter applied to all `/api/*` requests. Prevents abuse of the API as a whole.

#### requireJson (`src/middleware/requireJson.js`)

Rejects requests with a `Content-Type` other than `application/json`. This is a prerequisite for the strict JSON parser and CSRF protection.

#### express.json({ limit: '10kb', strict: true })

Parses the request body as JSON. `strict: true` rejects requests with unknown JSON properties. The 10 KB limit prevents large payload attacks.

#### createSessionMiddleware (`src/middleware/session.js`)

Configures `express-session` with `connect-pg-simple` as the session store. Key behaviors:

- Session cookie name uses the `__Host-` prefix in production.
- Rolling idle timeout is enforced on each request.
- Absolute session lifetime is enforced regardless of activity.
- `genid` generates cryptographically random session IDs.

#### authenticate (`src/middleware/authenticate.js`)

Attaches the current user to `req.user` by looking up the session's `userId` in the database. If the session is invalid, expired, or the user no longer exists, `req.user` is set to `null` and the session is destroyed.

#### csrfProtection (`src/middleware/csrf.js`)

For non-GET/HEAD/OPTIONS requests, validates the `X-CSRF-Token` header against the token stored in the session. GET requests to `/api/auth/csrf` generate and store a new CSRF token.

---

## API Reference

### Conventions

- **Base URL**: `/api`
- **Content-Type**: `application/json`
- **Authentication**: Session cookie (`gk.sid` or `__Host-gk.sid`) for authenticated endpoints.
- **CSRF**: All non-GET requests require the `X-CSRF-Token` header (obtain via `GET /api/auth/csrf`).
- **Error Format**:
  ```json
  {
  	"error": {
  		"code": "ERROR_CODE",
  		"message": "Human-readable error message",
  		"details": "Optional additional context"
  	}
  }
  ```

### Endpoints

#### Health Check

| Attribute   | Value                           |
| ----------- | ------------------------------- |
| **Method**  | `GET`                           |
| **Path**    | `/api/health`                   |
| **Auth**    | None                            |
| **Success** | `200 OK` — `{ "status": "ok" }` |

#### Get CSRF Token

| Attribute   | Value                                                                                                                                  |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| **Method**  | `GET`                                                                                                                                  |
| **Path**    | `/api/auth/csrf`                                                                                                                       |
| **Auth**    | None                                                                                                                                   |
| **Success** | `200 OK` — `{ "csrfToken": "..." }`                                                                                                    |
| **Notes**   | Creates an anonymous session. The returned token must be included in the `X-CSRF-Token` header for subsequent state-changing requests. |

#### Register

| Attribute        | Value                                                                                                                                                                                     |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Method**       | `POST`                                                                                                                                                                                    |
| **Path**         | `/api/auth/register`                                                                                                                                                                      |
| **Auth**         | None                                                                                                                                                                                      |
| **Request Body** | `{ "name": "string", "email": "string", "password": "string" }`                                                                                                                           |
| **Success**      | `201 Created` — `{ "message": "..." }`                                                                                                                                                    |
| **Errors**       | `422` (validation), `429` (rate limited)                                                                                                                                                  |
| **Notes**        | Returns the same response whether the email is new or existing. The user is NOT signed in automatically. If email verification is enabled, a verification email is sent for new accounts. |

#### Login

| Attribute        | Value                                                                                                            |
| ---------------- | ---------------------------------------------------------------------------------------------------------------- |
| **Method**       | `POST`                                                                                                           |
| **Path**         | `/api/auth/login`                                                                                                |
| **Auth**         | None                                                                                                             |
| **Request Body** | `{ "email": "string", "password": "string", "remember"?: boolean }`                                              |
| **Success**      | `200 OK` — `{ "user": { ... }, "csrfToken": "..." }`                                                             |
| **Errors**       | `401` (invalid credentials), `403` (email verification required), `422` (validation), `429` (rate limited)       |
| **Notes**        | Issues a new session ID (prevents fixation). `remember` extends the session lifetime to `SESSION_REMEMBER_DAYS`. |

#### Logout

| Attribute   | Value                         |
| ----------- | ----------------------------- |
| **Method**  | `POST`                        |
| **Path**    | `/api/auth/logout`            |
| **Auth**    | None (session-based)          |
| **Success** | `204 No Content`              |
| **Errors**  | `403` (CSRF failure)          |
| **Notes**   | Destroys the current session. |

#### Get Current User

| Attribute   | Value                                                                                                          |
| ----------- | -------------------------------------------------------------------------------------------------------------- |
| **Method**  | `GET`                                                                                                          |
| **Path**    | `/api/auth/me`                                                                                                 |
| **Auth**    | User (any authenticated user)                                                                                  |
| **Success** | `200 OK` — `{ "id": "uuid", "name": "string", "email": "string", "role": "string", "emailVerified": boolean }` |
| **Errors**  | `401` (not authenticated)                                                                                      |

#### Request Password Reset

| Attribute        | Value                                                                                                            |
| ---------------- | ---------------------------------------------------------------------------------------------------------------- |
| **Method**       | `POST`                                                                                                           |
| **Path**         | `/api/auth/forgot-password`                                                                                      |
| **Auth**         | None                                                                                                             |
| **Request Body** | `{ "email": "string" }`                                                                                          |
| **Success**      | `200 OK` — `{ "message": "..." }`                                                                                |
| **Errors**       | `429` (rate limited)                                                                                             |
| **Notes**        | Returns the same response whether the email exists or not. A reset link is sent via email if the account exists. |

#### Reset Password

| Attribute        | Value                                                                                                                                 |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| **Method**       | `POST`                                                                                                                                |
| **Path**         | `/api/auth/reset-password`                                                                                                            |
| **Auth**         | None                                                                                                                                  |
| **Request Body** | `{ "token": "string", "password": "string" }`                                                                                         |
| **Success**      | `200 OK` — `{ "message": "..." }`                                                                                                     |
| **Errors**       | `400` (invalid/expired token), `422` (validation)                                                                                     |
| **Notes**        | Consumes the token, updates the password, marks the email as verified, and signs out all devices (deletes all sessions for the user). |

#### Verify Email

| Attribute        | Value                                               |
| ---------------- | --------------------------------------------------- |
| **Method**       | `POST`                                              |
| **Path**         | `/api/auth/verify-email`                            |
| **Auth**         | None                                                |
| **Request Body** | `{ "token": "string" }`                             |
| **Success**      | `200 OK` — `{ "message": "..." }`                   |
| **Errors**       | `400` (invalid/expired token)                       |
| **Notes**        | Consumes the token and marks the email as verified. |

#### Resend Verification Email

| Attribute        | Value                                                                                                                             |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **Method**       | `POST`                                                                                                                            |
| **Path**         | `/api/auth/resend-verification`                                                                                                   |
| **Auth**         | None                                                                                                                              |
| **Request Body** | `{ "email": "string" }`                                                                                                           |
| **Success**      | `200 OK` — `{ "message": "..." }`                                                                                                 |
| **Errors**       | `429` (rate limited)                                                                                                              |
| **Notes**        | Returns the same response whether the email exists or not. No email is sent if the account is already verified or does not exist. |

#### Update Account

| Attribute        | Value                                         |
| ---------------- | --------------------------------------------- |
| **Method**       | `PATCH`                                       |
| **Path**         | `/api/account`                                |
| **Auth**         | User (any authenticated user)                 |
| **Request Body** | `{ "name": "string" }`                        |
| **Success**      | `200 OK` — updated user object                |
| **Errors**       | `401` (not authenticated), `422` (validation) |

#### List Users (Admin)

| Attribute        | Value                                                       |
| ---------------- | ----------------------------------------------------------- |
| **Method**       | `GET`                                                       |
| **Path**         | `/api/admin/users`                                          |
| **Query Params** | `page` (default: 1), `pageSize` (default: 20)               |
| **Auth**         | Admin only                                                  |
| **Success**      | `200 OK` — `{ "users": [...], "pagination": { ... } }`      |
| **Errors**       | `401` (not authenticated), `403` (insufficient permissions) |

#### Change User Role (Admin)

| Attribute        | Value                                                                                                     |
| ---------------- | --------------------------------------------------------------------------------------------------------- | ---------- |
| **Method**       | `PATCH`                                                                                                   |
| **Path**         | `/api/admin/users/:id/role`                                                                               |
| **Auth**         | Admin only                                                                                                |
| **Request Body** | `{ "role": "user"                                                                                         | "admin" }` |
| **Success**      | `200 OK` — updated user object                                                                            |
| **Errors**       | `401`, `403` (cannot change own role), `404` (user not found), `409` (role unchanged), `422` (validation) |

### Status Codes

| Code  | Meaning                                                               |
| ----- | --------------------------------------------------------------------- |
| `200` | Success                                                               |
| `201` | Created                                                               |
| `204` | No Content (success with no body)                                     |
| `400` | Bad request (e.g., invalid/expired token)                             |
| `401` | Unauthorized (not authenticated)                                      |
| `403` | Forbidden (authenticated but not permitted, or CSRF/Origin failure)   |
| `404` | Not found                                                             |
| `409` | Conflict (e.g., role unchanged)                                       |
| `422` | Validation error                                                      |
| `429` | Rate limited                                                          |
| `500` | Internal server error (logged server-side, generic message to client) |

---

## Authentication Flows

### Registration Flow

```
┌──────────┐       ┌──────────┐       ┌──────────┐       ┌──────────┐
│ Client   │       │ Express  │       │ Auth     │       │ PostgreSQL│
└────┬─────┘       └────┬─────┘       └────┬─────┘       └────┬─────┘
     │                   │                   │                   │
     │  POST /register   │                   │                   │
     │  {name,email,pass}│                   │                   │
     │──────────────────>│                   │                   │
     │                   │  validate input   │                   │
     │                   │──────────────────>│                   │
     │                   │                   │                   │
     │                   │  hashPassword()   │                   │
     │                   │──────────────────────────────────────>│
     │                   │                   │                   │
     │                   │  createUser()     │                   │
     │                   │──────────────────────────────────────>│
     │                   │                   │                   │
     │                   │                   │  issueToken()     │
     │                   │                   │──────────────────>│
     │                   │                   │                   │
     │                   │  send email       │                   │
     │                   │ (in background)   │                   │
     │                   │                   │                   │
     │  201 Created      │                   │                   │
     │<──────────────────│                   │                   │
     │                   │                   │                   │
```

### Login Flow

```
┌──────────┐       ┌──────────┐       ┌──────────┐       ┌──────────┐
│ Client   │       │ Express  │       │ Auth     │       │ PostgreSQL│
└────┬─────┘       └────┬─────┘       └────┬─────┘       └────┬─────┘
     │                   │                   │                   │
     │  GET /csrf        │                   │                   │
     │──────────────────>│                   │                   │
     │  200 {csrfToken}  │                   │                   │
     │<──────────────────│                   │                   │
     │                   │                   │                   │
     │  POST /login      │                   │                   │
     │  {email,password} │                   │                   │
     │  X-CSRF-Token: ...│                   │                   │
     │──────────────────>│                   │                   │
     │                   │  CSRF check       │                   │
     │                   │  Origin check     │                   │
     │                   │  Rate limit check │                   │
     │                   │                   │                   │
     │                   │  findCredentials  │                   │
     │                   │──────────────────────────────────────>│
     │                   │                   │                   │
     │                   │  verifyAgainstDummy (if no user)       │
     │                   │                   │                   │
     │                   │  verifyPassword()  │                   │
     │                   │                   │                   │
     │                   │  destroy old session│                  │
     │                   │  create new session│                  │
     │                   │──────────────────────────────────────>│
     │                   │                   │                   │
     │  200 {user,csrf}  │                   │                   │
     │<──────────────────│                   │                   │
     │                   │                   │                   │
```

### Password Reset Flow

```
┌──────────┐       ┌──────────┐       ┌──────────┐       ┌──────────┐
│ Client   │       │ Express  │       │ Auth     │       │  Email   │
└────┬─────┘       └────┬─────┘       └────┬─────┘       └────┬─────┘
     │                   │                   │                   │
     │  POST /forgot     │                   │                   │
     │  {email}          │                   │                   │
     │──────────────────>│                   │                   │
     │                   │  requestReset()   │                   │
     │                   │──────────────────>│                   │
     │                   │                   │  issueToken()     │
     │                   │                   │──────────────────>│
     │                   │                   │                   │
     │                   │                   │  send email       │
     │                   │                   │──────────────────────────────────>│
     │                   │                   │                   │
     │  200 {message}    │                   │                   │
     │<──────────────────│                   │                   │
     │                   │                   │                   │
     │  ... user clicks email link ...                                  │
     │                   │                   │                   │
     │  POST /reset      │                   │                   │
     │  {token,password} │                   │                   │
     │──────────────────>│                   │                   │
     │                   │  consumeToken()   │                   │
     │                   │  updatePasswordHash│                  │
     │                   │  markEmailVerified│                  │
     │                   │  deleteAllSessions│                  │
     │                   │──────────────────────────────────────>│
     │                   │                   │                   │
     │  200 {message}    │                   │                   │
     │<──────────────────│                   │                   │
     │                   │                   │                   │
```

---

## Role-Based Access Control

Gatekeeper supports two roles out of the box: `user` and `admin`.

### Role Definitions

| Role    | Permissions                                                                              |
| ------- | ---------------------------------------------------------------------------------------- |
| `user`  | Access to their own account (`/api/account`), authentication endpoints.                  |
| `admin` | All `user` permissions, plus access to admin routes (`/api/admin/*`) for managing users. |

### How Roles Are Enforced

Roles are enforced via middleware in the route definitions:

- **Public Routes**: No authentication required (e.g., `/api/auth/register`, `/api/auth/login`).
- **User Routes**: The `authenticate` middleware attaches `req.user`. If the user is not authenticated, the request is rejected with `401`.
- **Admin Routes**: The `authenticate` middleware is followed by a role check. If `req.user.role !== 'admin'`, the request is rejected with `403`.

### Admin Capabilities

Admins can:

- **List all users** with pagination (`GET /api/admin/users`).
- **Change user roles** (`PATCH /api/admin/users/:id/role`).
- **Prevent self-demotion**: Admins cannot change their own role.

### Creating Admin Users

Admin users are created via the CLI script:

```bash
npm run create-admin -- admin@example.com "Admin Name"
```

This creates a user with the `admin` role. You can also promote an existing user to admin by updating their role directly in the database or via the admin API.

---

## Error Handling

Gatekeeper uses a centralized error handling middleware (`src/middleware/errorHandler.js`).

### Error Format

All errors returned to clients follow this structure:

```json
{
	"error": {
		"code": "ERROR_CODE",
		"message": "Human-readable error message",
		"details": "Optional additional context"
	}
}
```

### Custom Error Class

The application uses `AppError` (from `src/utils/AppError.js`) for consistent error creation:

```javascript
import { AppError } from '../utils/AppError.js';

// Example: throw new AppError(401, 'INVALID_CREDENTIALS', 'Invalid email or password.');
```

### Error Codes

| Code                  | HTTP Status | Description                                       |
| --------------------- | ----------- | ------------------------------------------------- |
| `INVALID_CREDENTIALS` | 401         | Email or password is incorrect.                   |
| `EMAIL_NOT_VERIFIED`  | 403         | Email verification is required but not completed. |
| `INVALID_TOKEN`       | 400         | Token is malformed, expired, or already used.     |
| `VALIDATION_ERROR`    | 422         | Input failed validation (detailed in `details`).  |
| `RATE_LIMIT_EXCEEDED` | 429         | Too many requests.                                |
| `NOT_FOUND`           | 404         | Resource not found.                               |
| `CONFLICT`            | 409         | Resource state conflict (e.g., role unchanged).   |
| `FORBIDDEN`           | 403         | Authenticated but not permitted.                  |
| `INTERNAL_ERROR`      | 500         | Unexpected server error.                          |

### Client-Side Error Handling

The frontend API client (`public/js/api.js`) parses error responses and surfaces them to the user. Generic error messages are displayed for 500-level errors to avoid information leakage.

---

## Frontend Architecture

Gatekeeper's frontend is a **single-page application (SPA)** built with vanilla JavaScript and served as static assets by Express.

### File Organization

```
public/
├── index.html          # Application shell with view containers
├── css/
│   └── styles.css      # Global styles, responsive layout
└── js/
    ├── api.js          # API client wrapper (Fetch API + CSRF token injection)
    ├── app.js          # UI logic, view routing, form submission handlers
    └── validators.js   # Client-side form validation (mirrors server-side rules)
```

### API Client (`public/js/api.js`)

The API client wraps the browser's Fetch API with:

- **Automatic CSRF token injection**: Reads the `X-CSRF-Token` cookie and includes it in the `X-CSRF-Token` header for non-GET requests.
- **Token removal from URL**: On page load, removes the `token` query parameter from the address bar to prevent token leakage via Referer headers or browser history.
- **Consistent error handling**: Parses error responses and throws descriptive errors.
- **Session awareness**: Handles redirects to login when the server returns `401`.

### UI Logic (`public/js/app.js`)

- **View Routing**: Shows/hides view containers based on the current route (hash-based routing).
- **Form Handling**: Intercepts form submissions, validates input, and calls the API client.
- **State Management**: Tracks the current user and authentication state in memory.

### Client-Side Validation (`public/js/validators.js`)

Provides real-time feedback for:

- Name length and character restrictions.
- Email format.
- Password length (minimum 10 characters).
- Password confirmation matching.

> **Note**: Client-side validation is a usability feature, not a security control. All validation is re-checked on the server.

### Security Considerations

- **No `innerHTML`**: The frontend never uses `innerHTML` or `insertAdjacentHTML` with untrusted input, preventing XSS even if CSP is bypassed.
- **`textContent` only**: User-generated content is rendered using `textContent` or text nodes.
- **CSP Compliance**: All inline scripts use nonces or are placed in separate JS files to comply with the strict CSP.

---

## Testing

### Test Framework

Gatekeeper uses **Node's built-in test runner** (`node:test`) combined with **Supertest** for HTTP integration tests.

### Running Tests

```bash
npm test
```

This runs 58+ integration tests against a real PostgreSQL instance.

### Test Database

Tests require a separate database specified by `TEST_DATABASE_URL`. The name must contain `test` to prevent accidental runs against the production database.

```bash
# Example test database URL
TEST_DATABASE_URL=postgresql://gatekeeper:change_me@localhost:5432/gatekeeper_test
```

### Test Concurrency

Tests run with `--test-concurrency=1` to avoid database race conditions during integration tests.

### Test Database Migrations

Test migrations are run automatically or can be triggered manually:

```bash
npm run db:migrate:test
```

### Writing Tests

Tests are located in the `tests/` directory. They use the following patterns:

- **Setup/Teardown**: Tests create and clean up their own data within transactions.
- **Supertest**: HTTP assertions are made using Supertest's chaining API.
- **Assertions**: Node's built-in `test.assert` or the `node:test` `expect` API.

### CI Considerations

- Run `npm test` in CI with `TEST_DATABASE_URL` configured.
- Run `npm run audit` to check for dependency vulnerabilities.
- Ensure the test database is created and migrated before running tests.

---

## Production Deployment

### Pre-Deployment Checklist

1. **HTTPS Only**: Set `NODE_ENV=production` and `APP_URL=https://your-domain.com`.
2. **Session Secret**: Generate a strong `SESSION_SECRET` (≥ 64 characters recommended). Use the comma-separated format for key rotation.
3. **Database SSL**: Set `DATABASE_SSL=true` for remote PostgreSQL connections.
4. **SMTP Configuration**: Set `EMAIL_TRANSPORT=smtp` and configure `SMTP_*` variables with a real mail server.
5. **Cookie Security**: Ensure `COOKIE_SECURE=true` (enforced in production).
6. **Argon2 Parameters**: Verify `ARGON2_MEMORY_KIB >= 19456` and `ARGON2_TIME_COST >= 2` (enforced in production).
7. **Trust Proxy**: Set `TRUST_PROXY` to the correct number of hops if behind a reverse proxy (e.g., `1` for a single load balancer).
8. **CORS Origins**: Configure `CORS_ORIGINS` with your frontend's origin(s) if the frontend is served from a different domain.
9. **Least-Privilege DB User**: Use a database user with only the necessary permissions (no superuser, no DDL rights at runtime if migrations are run separately).
10. **Run Migrations**: `npm run db:migrate`
11. **Create Admin**: `npm run create-admin -- admin@example.com "Admin Name"`
12. **Run Audit**: `npm run audit` to check for known vulnerabilities.

### Deployment Options

#### Option 1: Direct Node.js Process

```bash
NODE_ENV=production node src/server.js
```

Use a process manager like **PM2** or **systemd** for process supervision, auto-restart, and logging.

#### Option 2: Docker

Create a `Dockerfile`:

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run db:migrate
EXPOSE 3000
CMD ["node", "src/server.js"]
```

#### Option 3: Reverse Proxy (Nginx)

If using a reverse proxy:

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    client_max_body_size 10K;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Set `TRUST_PROXY=1` in your environment to ensure correct IP logging and `Secure` cookie behavior.

### Environment Variables (Production)

```env
NODE_ENV=production
PORT=3000
APP_URL=https://your-domain.com
DATABASE_URL=postgresql://gatekeeper:strong-password@db-host:5432/gatekeeper?sslmode=require
SESSION_SECRET=<64+ char secret>,<previous secret for rotation>
COOKIE_SECURE=true
COOKIE_SAMESITE=lax
TRUST_PROXY=1
EMAIL_TRANSPORT=smtp
SMTP_HOST=smtp.mailgun.org
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=postmaster@your-domain.com
SMTP_PASS=your-smtp-password
EMAIL_FROM=Gatekeeper <noreply@your-domain.com>
CORS_ORIGINS=https://your-frontend-domain.com
ARGON2_MEMORY_KIB=19456
ARGON2_TIME_COST=2
EMAIL_VERIFICATION=optional
RESET_TOKEN_MINUTES=30
VERIFY_TOKEN_HOURS=24
RATE_LIMIT_ENABLED=true
```

---

## Maintenance & Operations

### Logging

Gatekeeper logs to `stdout`/`stderr`. In production:

- Use a process manager (PM2, systemd) to capture logs.
- Pipe logs to a centralized logging service (e.g., ELK, Datadog, CloudWatch).
- Notable log events:
  - Database connection failures at startup.
  - Password rehash failures (logged as errors).
  - Unhandled rejections.

### Database Maintenance

- **Vacuum**: PostgreSQL's autovacuum handles routine maintenance. Monitor for bloat if you have high churn.
- **Indexes**: Consider adding `(sess->>'userId')` on the `session` table if you have many concurrent sessions and sign-out-all-devices is slow.
- **Backups**: Regular PostgreSQL backups are essential. Use `pg_dump` or your cloud provider's backup solution.

### Monitoring

Monitor the following metrics:

| Metric                         | Why                                  |
| ------------------------------ | ------------------------------------ |
| Response time (p95, p99)       | Detect performance degradation.      |
| Error rate (4xx, 5xx)          | Detect misconfigurations or attacks. |
| Database connection pool usage | Prevent pool exhaustion.             |
| Rate limit hits                | Detect brute-force attempts.         |
| Session count                  | Monitor session store growth.        |
| Email delivery failures        | Detect SMTP issues.                  |

### Updating Dependencies

```bash
npm audit          # Check for vulnerabilities
npm update         # Update dependencies
npm test           # Verify tests pass
```

### Graceful Shutdown

Gatekeeper handles `SIGTERM` and `SIGINT` signals gracefully:

1. Stops accepting new connections.
2. Closes the database connection pool.
3. Exits with code 0.

This ensures in-flight requests complete and database connections are cleanly released.

---

## Known Trade-offs & Roadmap

### Current Trade-offs

1. **Registration does not auto-login**: Registration returns the same message for new and existing emails to prevent account enumeration. Users must log in separately. This adds one step but significantly improves privacy.

2. **In-memory rate limiters**: Rate limit counters are stored in process memory. For horizontal scaling (multiple instances), use a shared store (e.g., `rate-limit-redis`) or enforce rate limits at the reverse proxy level.

3. **Session cleanup performance**: Signing out all devices requires a sequential scan of the `session` table's JSON `sess` column. For high-volume deployments, convert `sess` to `jsonb` and add an index on `(sess->>'userId')`.

4. **No built-in MFA**: Multi-factor authentication is not implemented. This is a natural next step for teams that require it.

5. **No "change password while signed in"**: Users cannot change their password without requesting a reset. This is a planned feature.

6. **No account deletion**: Users cannot delete their own accounts. This is a planned feature.

### Planned Features

- Multi-factor authentication (TOTP, WebAuthn).
- "Change password" flow while authenticated.
- Account deletion with data purge.
- OAuth2 / OpenID Connect provider integration.
- Session management UI (view and revoke active sessions).
- Password breach checking (Have I Been Pwned API integration).
- Redis-backed rate limiting for horizontal scaling.

---

## FAQ & Troubleshooting

### Q: Why does registration not log me in automatically?

A: This is intentional. To prevent attackers from discovering which email addresses are registered, Gatekeeper returns the same response for both new and existing emails. Automatic login would require revealing whether the email was new, which would leak account existence.

### Q: How do I rotate session secrets?

A: Set `SESSION_SECRET` as a comma-separated list with the newest secret first:

```
SESSION_SECRET=new_secret_here,old_secret_here,older_secret_here
```

Gatekeeper will validate sessions signed with any of the listed secrets and issue new sessions signed with the first (newest) secret.

### Q: Why is my email not being sent in development?

A: In development (`NODE_ENV=development`), the default `EMAIL_TRANSPORT` is `console`, which prints emails to the terminal. Set `EMAIL_TRANSPORT=smtp` and configure `SMTP_*` variables if you want to send real emails in development.

### Q: How do I reset the admin password?

A: Use the password reset flow through the application UI, or directly update the `password_hash` in the `users` table:

```sql
UPDATE users SET password_hash = '<new-argon2-hash>' WHERE email = 'admin@example.com';
```

Alternatively, create a new admin user:

```bash
npm run create-admin -- newadmin@example.com "New Admin"
```

### Q: Why am I getting `COOKIE_SECURE must be true in production`?

A: In production, Gatekeeper enforces secure cookies to prevent session theft over unencrypted connections. Ensure `NODE_ENV=production` and `COOKIE_SECURE=true` are set, and serve the application over HTTPS.

### Q: How do I scale Gatekeeper horizontally?

A: For multiple instances:

1. Use a shared PostgreSQL database (already supported).
2. Replace the in-memory rate limiters with a shared store (e.g., `rate-limit-redis`).
3. If using a reverse proxy, set `TRUST_PROXY` correctly.
4. Ensure sticky sessions are NOT used — sessions are stored in PostgreSQL and are instance-agnostic.

### Q: Why is the login slow?

A: Login involves an Argon2id password verification, which is intentionally CPU-intensive (19 MiB, 2 passes). This is a security feature to slow down brute-force attacks. If performance is a concern, ensure your server has adequate CPU resources. You can slightly reduce `ARGON2_MEMORY_KIB` (minimum 19456) or `ARGON2_TIME_COST` (minimum 2), but this weakens security.

### Q: Why am I logged out after a short time?

A: Check your session timeout settings:

- `SESSION_IDLE_MINUTES`: Rolling idle timeout (default: 120 minutes).
- `SESSION_ABSOLUTE_DAYS`: Hard maximum lifetime (default: 30 days).

If the session expires, the user must log in again. You can adjust these in your environment variables.

### Q: How do I add a new role?

A: Modify the `role` `CHECK` constraint in `db/schema.sql` and the `role` validation in `src/middleware/authenticate.js` (or wherever roles are checked). Update `npm run db:migrate` to apply the schema change.

### Q: Is Gatekeeper GDPR compliant?

A: Gatekeeper provides features that support GDPR compliance (data minimization, secure storage, account management), but full compliance depends on your deployment, data processing agreements, and legal review. The "account deletion" feature (planned) will further support GDPR right-to-erasure requests.
