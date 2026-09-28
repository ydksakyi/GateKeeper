// All user SQL lives here. Every query is parameterised; values are never concatenated into SQL.
import { pool } from './pool.js';

const PUBLIC_COLUMNS = 'id, name, email, role, email_verified_at, created_at';

// The only shape of a user that ever leaves the data layer for API use: no password hash.
export const toPublicUser = (row) =>
  row && {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    emailVerified: Boolean(row.email_verified_at),
    createdAt: row.created_at,
  };

export async function findById(id) {
  const { rows } = await pool.query(`SELECT ${PUBLIC_COLUMNS} FROM users WHERE id = $1`, [id]);
  return toPublicUser(rows[0]) ?? null;
}

// Includes password_hash. Use only for credential checks; never serialise the result.
export async function findCredentialsByEmail(email) {
  const { rows } = await pool.query(`SELECT ${PUBLIC_COLUMNS}, password_hash FROM users WHERE email = $1`, [email]);
  return rows[0] ?? null;
}

// Returns the new user, or null if the email is already registered.
export async function createUser({ name, email, passwordHash, role = 'user', verified = false }) {
  const { rows } = await pool.query(
    `INSERT INTO users (name, email, password_hash, role, email_verified_at)
     VALUES ($1, $2, $3, $4, CASE WHEN $5::boolean THEN now() END)
     ON CONFLICT (email) DO NOTHING
     RETURNING ${PUBLIC_COLUMNS}`,
    [name, email, passwordHash, role, verified],
  );
  return toPublicUser(rows[0]) ?? null;
}

export async function updatePasswordHash(db, id, passwordHash) {
  await db.query('UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1', [id, passwordHash]);
}

export async function markEmailVerified(db, id) {
  await db.query(
    'UPDATE users SET email_verified_at = COALESCE(email_verified_at, now()), updated_at = now() WHERE id = $1',
    [id],
  );
}

export async function updateName(id, name) {
  const { rows } = await pool.query(
    `UPDATE users SET name = $2, updated_at = now() WHERE id = $1 RETURNING ${PUBLIC_COLUMNS}`,
    [id, name],
  );
  return toPublicUser(rows[0]) ?? null;
}

export async function updateRole(id, role) {
  const { rows } = await pool.query(
    `UPDATE users SET role = $2, updated_at = now() WHERE id = $1 RETURNING ${PUBLIC_COLUMNS}`,
    [id, role],
  );
  return toPublicUser(rows[0]) ?? null;
}

export async function list({ limit, offset }) {
  const { rows } = await pool.query(
    `SELECT ${PUBLIC_COLUMNS} FROM users ORDER BY created_at DESC, id LIMIT $1 OFFSET $2`,
    [limit, offset],
  );
  return rows.map(toPublicUser);
}

export async function count() {
  const { rows } = await pool.query('SELECT count(*)::int AS n FROM users');
  return rows[0].n;
}

// Signs the user out everywhere (used after a password reset).
export async function deleteSessionsForUser(db, userId) {
  await db.query("DELETE FROM session WHERE sess->>'userId' = $1", [userId]);
}
