import { pool } from './pool.js';

// Invalidate earlier unused tokens of the same purpose, then store the new hash.
export async function replaceToken({ userId, purpose, tokenHash, expiresAt }) {
  await pool.query(
    'UPDATE auth_tokens SET used_at = now() WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL',
    [userId, purpose],
  );
  await pool.query(
    'INSERT INTO auth_tokens (user_id, purpose, token_hash, expires_at) VALUES ($1, $2, $3, $4)',
    [userId, purpose, tokenHash, expiresAt],
  );
}

// Atomic single-use consumption: exactly one caller can flip used_at from NULL.
export async function consume(db, { tokenHash, purpose }) {
  const { rows } = await db.query(
    `UPDATE auth_tokens SET used_at = now()
      WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > now()
      RETURNING user_id`,
    [tokenHash, purpose],
  );
  return rows[0]?.user_id ?? null;
}

export async function purgeExpired() {
  await pool.query("DELETE FROM auth_tokens WHERE expires_at < now() - interval '7 days'");
}
