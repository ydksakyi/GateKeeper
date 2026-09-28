import fs from 'node:fs';
import { pool } from '../../src/db/pool.js';

const schema = fs.readFileSync(new URL('../../db/schema.sql', import.meta.url), 'utf8');

export async function setupDb() {
  await pool.query(schema);
}
export async function resetDb() {
  await pool.query('TRUNCATE users, auth_tokens, session RESTART IDENTITY CASCADE');
}
export async function closeDb() {
  await pool.end();
}
