import './helpers/env.js';
import { test, describe, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { pool } from '../src/db/pool.js';
import { setupDb, resetDb, closeDb } from './helpers/db.js';
import { createClient, registerAndLogin, makeAdmin, uniqueEmail } from './helpers/client.js';

const app = createApp();

before(setupDb);
beforeEach(resetDb);
after(closeDb);

async function adminClient() {
  const email = uniqueEmail();
  const session = await registerAndLogin(app, { email });
  await makeAdmin(email); // role is read fresh on each request, so no re-login needed
  return { ...session, email };
}

describe('authorization', () => {
  test('anonymous requests to private and admin routes get 401', async () => {
    const anon = createClient(app);
    assert.equal((await anon.get('/api/admin/users')).status, 401);
    assert.equal((await anon.patch('/api/account', { name: 'Ama Serwaa' })).status, 401);
  });

  test('a regular user gets 403 on admin endpoints', async () => {
    const { client } = await registerAndLogin(app);
    const list = await client.get('/api/admin/users');
    assert.equal(list.status, 403);
    assert.equal(list.body.error.code, 'FORBIDDEN');
    const target = await pool.query('SELECT id FROM users LIMIT 1');
    assert.equal((await client.patch(`/api/admin/users/${target.rows[0].id}/role`, { role: 'admin' })).status, 403);
    const { rows } = await pool.query('SELECT role FROM users');
    assert.equal(rows[0].role, 'user'); // privilege escalation attempt changed nothing
  });

  test('an admin can list users without any secret fields', async () => {
    const { client } = await adminClient();
    await registerAndLogin(app);
    const res = await client.get('/api/admin/users');
    assert.equal(res.status, 200);
    assert.equal(res.body.total, 2);
    const text = JSON.stringify(res.body);
    assert.ok(!text.includes('password'));
    assert.ok(!text.includes('argon2'));
  });

  test('an admin can change another user\'s role, and it applies immediately', async () => {
    const { client } = await adminClient();
    const other = await registerAndLogin(app);
    const id = (await other.client.get('/api/auth/me')).body.user.id;

    assert.equal((await other.client.get('/api/admin/users')).status, 403);
    const res = await client.patch(`/api/admin/users/${id}/role`, { role: 'admin' });
    assert.equal(res.status, 200);
    assert.equal(res.body.user.role, 'admin');
    assert.equal((await other.client.get('/api/admin/users')).status, 200);
  });

  test('admins cannot change their own role', async () => {
    const { client } = await adminClient();
    const id = (await client.get('/api/auth/me')).body.user.id;
    const res = await client.patch(`/api/admin/users/${id}/role`, { role: 'user' });
    assert.equal(res.status, 409);
    assert.equal(res.body.error.code, 'CANNOT_MODIFY_SELF');
  });

  test('role changes validate the id and the role', async () => {
    const { client } = await adminClient();
    assert.equal((await client.patch('/api/admin/users/not-a-uuid/role', { role: 'user' })).status, 422);
    const id = '00000000-0000-4000-8000-000000000000';
    assert.equal((await client.patch(`/api/admin/users/${id}/role`, { role: 'superuser' })).status, 422);
    assert.equal((await client.patch(`/api/admin/users/${id}/role`, { role: 'user' })).status, 404);
  });

  test('a signed-in user can update their own name; markup is rejected', async () => {
    const { client } = await registerAndLogin(app);
    const ok = await client.patch('/api/account', { name: "Kofi O'Brien-Mensah" });
    assert.equal(ok.status, 200);
    assert.equal(ok.body.user.name, "Kofi O'Brien-Mensah");
    const bad = await client.patch('/api/account', { name: '<img src=x onerror=alert(1)>' });
    assert.equal(bad.status, 422);
  });

  test('unknown API routes return a JSON 404', async () => {
    const res = await request(app).get('/api/nope');
    assert.equal(res.status, 404);
    assert.equal(res.body.error.code, 'NOT_FOUND');
  });
});
