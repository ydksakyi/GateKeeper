-- Gatekeeper schema. Idempotent: safe to run repeatedly. Requires PostgreSQL 13+.

CREATE TABLE IF NOT EXISTS users (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name              varchar(80)  NOT NULL,
  email             varchar(254) NOT NULL,
  password_hash     text         NOT NULL,
  role              varchar(16)  NOT NULL DEFAULT 'user',
  email_verified_at timestamptz,
  created_at        timestamptz  NOT NULL DEFAULT now(),
  updated_at        timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT users_role_check  CHECK (role IN ('user', 'admin')),
  CONSTRAINT users_email_lower CHECK (email = lower(email))
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_key ON users (email);

-- Single-use, expiring tokens. Only the SHA-256 hash is stored, never the token itself.
CREATE TABLE IF NOT EXISTS auth_tokens (
  id         bigserial PRIMARY KEY,
  user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  purpose    varchar(32) NOT NULL,
  token_hash char(64)    NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT auth_tokens_purpose_check CHECK (purpose IN ('password_reset', 'email_verify'))
);
CREATE UNIQUE INDEX IF NOT EXISTS auth_tokens_hash_key ON auth_tokens (token_hash);
CREATE INDEX IF NOT EXISTS auth_tokens_user_purpose_idx ON auth_tokens (user_id, purpose);

-- Server-side sessions (schema required by connect-pg-simple).
CREATE TABLE IF NOT EXISTS session (
  sid    varchar      NOT NULL PRIMARY KEY,
  sess   json         NOT NULL,
  expire timestamp(6) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_expire ON session (expire);
