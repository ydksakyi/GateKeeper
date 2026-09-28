import './helpers/env.js';
import { test, describe, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { pool } from '../src/db/pool.js';
import { outbox } from '../src/services/email.js';
import { hashToken } from '../src/services/tokens.js';
import { setupDb, resetDb, closeDb } from './helpers/db.js';
import { PASSWORD, createClient, register, registerAndLogin, patchConfig, lastMail, tokenFrom, sessionCookie, uniqueEmail } from './helpers/client.js';

const app = createApp();

before(setupDb);
beforeEach(async () => {
  await resetDb();
  outbox.length = 0;
});
after(closeDb);

describe('registration', () => {
  test('stores an Argon2id hash and never the plaintext password', async () => {
    const client = createClient(app);
    const res = await client.post('/api/auth/register', { name: 'Ama Serwaa', email: 'Ama@Example.com', password: PASSWORD });
    assert.equal(res.status, 201);
    assert.ok(!JSON.stringify(res.body).includes(PASSWORD));

    const { rows } = await pool.query('SELECT * FROM users');
    assert.equal(rows.length, 1);
    assert.equal(rows[0].email, 'ama@example.com'); // normalised
    assert.match(rows[0].password_hash, /^\$argon2id\$/);
    assert.ok(!rows[0].password_hash.includes(PASSWORD));
    assert.equal(rows[0].role, 'user');
  });

  test('cannot self-assign a role or verification status', async () => {
    const client = createClient(app);
    await client.post('/api/auth/register', { name: 'Kofi Mensah', email: 'kofi@example.com', password: PASSWORD, role: 'admin', emailVerified: true });
    const { rows } = await pool.query('SELECT role, email_verified_at FROM users');
    assert.equal(rows[0].role, 'user');
    assert.equal(rows[0].email_verified_at, null);
  });

  const invalid = [
    ['markup in name', { name: '<script>alert(1)</script>' }, 'name'],
    ['digits in name', { name: 'Kofi 123' }, 'name'],
    ['too-short name', { name: 'K' }, 'name'],
    ['malformed email', { email: 'not-an-email' }, 'email'],
    ['email with SQL', { email: "a@b.co' OR '1'='1" }, 'email'],
    ['short password', { password: 'short' }, 'password'],
    ['common password', { password: 'password123' }, 'password'],
    ['repeated character password', { password: 'aaaaaaaaaaaa' }, 'password'],
    ['object instead of string', { name: { $ne: 1 } }, 'name'],
    ['array email', { email: ['a@b.co'] }, 'email'],
  ];
  for (const [label, override, field] of invalid) {
    test(`rejects ${label}`, async () => {
      const client = createClient(app);
      const res = await client.post('/api/auth/register', { name: 'Ama Serwaa', email: uniqueEmail(), password: PASSWORD, ...override });
      assert.equal(res.status, 422);
      assert.equal(res.body.error.code, 'VALIDATION_ERROR');
      assert.ok(res.body.error.details[field], `expected an error for ${field}`);
      const { rows } = await pool.query('SELECT 1 FROM users');
      assert.equal(rows.length, 0);
    });
  }

  test('a duplicate email is indistinguishable from a new one and creates no second account', async () => {
    const first = await register(createClient(app), { email: 'dup@example.com' });
    outbox.length = 0;
    const second = await register(createClient(app), { email: 'dup@example.com', name: 'Someone Else' });

    assert.equal(second.res.status, first.res.status);
    assert.deepEqual(second.res.body, first.res.body);
    const { rows } = await pool.query('SELECT name FROM users');
    assert.equal(rows.length, 1);
    assert.equal(rows[0].name, 'Ama Serwaa');
    assert.equal(lastMail('dup@example.com').subject, 'You already have an account');
  });
});

describe('login, sessions and logout', () => {
  test('logs in and sets a hardened session cookie', async () => {
    const { client, data, res } = await registerAndLogin(app);
    assert.equal(res.body.user.email, data.email);
    assert.equal(res.body.user.password_hash, undefined);
    assert.ok(!JSON.stringify(res.body).includes('argon2'));

    const cookie = res.headers['set-cookie'].find((c) => c.startsWith('gk.sid='));
    assert.match(cookie, /HttpOnly/i);
    assert.match(cookie, /SameSite=Lax/i);
    assert.match(cookie, /Path=\//);

    const me = await client.get('/api/auth/me');
    assert.equal(me.status, 200);
    assert.equal(me.body.user.email, data.email);
  });

  test('wrong password and unknown email return the same generic 401', async () => {
    const { data } = await registerAndLogin(app);
    const c = createClient(app);
    const wrongPassword = await c.post('/api/auth/login', { email: data.email, password: 'definitely-not-it' });
    const unknownEmail = await c.post('/api/auth/login', { email: 'nobody@example.com', password: 'definitely-not-it' });
    assert.equal(wrongPassword.status, 401);
    assert.equal(unknownEmail.status, 401);
    assert.deepEqual(wrongPassword.body, unknownEmail.body);
    assert.equal(wrongPassword.body.error.message, 'Invalid email or password.');
  });

  test('issues a new session id at login (session fixation defence)', async () => {
    const client = createClient(app);
    const { data } = await register(client);
    const pre = await client.agent.get('/api/auth/csrf');
    const preCookie = sessionCookie(pre);
    assert.ok(preCookie);
    client.setCsrf(pre.body.csrfToken);

    const login = await client.post('/api/auth/login', { email: data.email, password: data.password });
    const postCookie = sessionCookie(login);
    assert.ok(postCookie);
    assert.notEqual(postCookie, preCookie);

    // The pre-login session id must be worthless afterwards.
    const replay = await request(app).get('/api/auth/me').set('Cookie', preCookie);
    assert.equal(replay.status, 401);
  });

  test('/api/auth/me requires authentication', async () => {
    const res = await request(app).get('/api/auth/me');
    assert.equal(res.status, 401);
    assert.equal(res.body.error.code, 'UNAUTHENTICATED');
  });

  test('logout destroys the session server-side, so a stolen cookie stops working', async () => {
    const { client, res } = await registerAndLogin(app);
    const stolen = sessionCookie(res);
    assert.equal((await request(app).get('/api/auth/me').set('Cookie', stolen)).status, 200);

    const out = await client.post('/api/auth/logout');
    assert.equal(out.status, 204);
    assert.equal((await client.get('/api/auth/me')).status, 401);
    assert.equal((await request(app).get('/api/auth/me').set('Cookie', stolen)).status, 401);
    const { rows } = await pool.query('SELECT 1 FROM session WHERE sess::jsonb ? \'userId\'');
    assert.equal(rows.length, 0);
  });

  test('idle-expired sessions are rejected', async () => {
    const { client } = await registerAndLogin(app);
    await pool.query("UPDATE session SET expire = now() - interval '1 minute'");
    assert.equal((await client.get('/api/auth/me')).status, 401);
  });

  test('sessions past their absolute lifetime are rejected even if recently active', async () => {
    const { client } = await registerAndLogin(app);
    const old = Date.now() - 31 * 24 * 60 * 60 * 1000;
    await pool.query("UPDATE session SET sess = jsonb_set(sess::jsonb, '{createdAt}', to_jsonb($1::bigint))::json", [old]);
    assert.equal((await client.get('/api/auth/me')).status, 401);
  });

  test('"remember me" gives a longer-lived cookie than a normal login', async () => {
    const client = createClient(app);
    const { data } = await register(client);
    const normal = await client.post('/api/auth/login', { email: data.email, password: data.password });
    const remembered = await createClient(app).post('/api/auth/login', { email: data.email, password: data.password, remember: true });
    const expires = (res) => new Date(res.headers['set-cookie'][0].match(/Expires=([^;]+)/)[1]).getTime();
    assert.ok(expires(remembered) - expires(normal) > 7 * 24 * 60 * 60 * 1000);
  });

  test('a deleted user loses access immediately', async () => {
    const { client, data } = await registerAndLogin(app);
    await pool.query('DELETE FROM users WHERE email = $1', [data.email]);
    assert.equal((await client.get('/api/auth/me')).status, 401);
  });
});

describe('email verification', () => {
  test('verification email is sent, token works once, and only its hash is stored', async () => {
    const client = createClient(app);
    const { data } = await register(client);
    const token = tokenFrom(lastMail(data.email));

    const { rows } = await pool.query('SELECT token_hash FROM auth_tokens');
    assert.equal(rows[0].token_hash, hashToken(token));
    assert.notEqual(rows[0].token_hash, token);

    assert.equal((await client.post('/api/auth/verify-email', { token })).status, 200);
    const user = await pool.query('SELECT email_verified_at FROM users WHERE email = $1', [data.email]);
    assert.ok(user.rows[0].email_verified_at);
    assert.equal((await client.post('/api/auth/verify-email', { token })).status, 400); // single use
  });

  test('expired and garbage tokens are rejected', async () => {
    const client = createClient(app);
    const { data } = await register(client);
    const token = tokenFrom(lastMail(data.email));
    await pool.query("UPDATE auth_tokens SET expires_at = now() - interval '1 minute'");
    assert.equal((await client.post('/api/auth/verify-email', { token })).status, 400);
    assert.equal((await client.post('/api/auth/verify-email', { token: 'x'.repeat(43) })).status, 400);
  });

  describe('when verification is required', () => {
    let restore;
    before(() => { restore = patchConfig({ emailVerification: 'required' }); });
    after(() => restore());

    test('blocks login until the address is verified', async () => {
      const client = createClient(app);
      const { data } = await register(client);
      const blocked = await client.post('/api/auth/login', { email: data.email, password: data.password });
      assert.equal(blocked.status, 403);
      assert.equal(blocked.body.error.code, 'EMAIL_NOT_VERIFIED');

      await client.post('/api/auth/verify-email', { token: tokenFrom(lastMail(data.email)) });
      const ok = await client.post('/api/auth/login', { email: data.email, password: data.password });
      assert.equal(ok.status, 200);
    });

    test('a wrong password still returns the generic 401, not the verification error', async () => {
      const client = createClient(app);
      const { data } = await register(client);
      const res = await client.post('/api/auth/login', { email: data.email, password: 'wrong-password-here' });
      assert.equal(res.status, 401);
    });
  });
});

describe('password reset', () => {
  test('unknown and known emails get identical responses; only the known one gets mail', async () => {
    const { data } = await registerAndLogin(app);
    outbox.length = 0;
    const c = createClient(app);
    const unknown = await c.post('/api/auth/forgot-password', { email: 'ghost@example.com' });
    assert.equal(outbox.length, 0);
    const known = await c.post('/api/auth/forgot-password', { email: data.email });
    assert.equal(unknown.status, 200);
    assert.deepEqual(unknown.body, known.body);
    assert.equal(lastMail(data.email).subject, 'Reset your password');
  });

  test('reset link changes the password once, signs out other sessions, and cannot be reused', async () => {
    const { client: signedIn, data } = await registerAndLogin(app);
    outbox.length = 0;
    const other = createClient(app);
    await other.post('/api/auth/forgot-password', { email: data.email });
    const token = tokenFrom(lastMail(data.email));

    const newPassword = 'a-brand-new-passphrase';
    assert.equal((await other.post('/api/auth/reset-password', { token, password: newPassword })).status, 200);

    assert.equal((await signedIn.get('/api/auth/me')).status, 401); // old sessions revoked
    const c = createClient(app);
    assert.equal((await c.post('/api/auth/login', { email: data.email, password: data.password })).status, 401);
    assert.equal((await c.post('/api/auth/login', { email: data.email, password: newPassword })).status, 200);
    assert.equal((await other.post('/api/auth/reset-password', { token, password: 'yet-another-passphrase' })).status, 400);
  });

  test('a weak new password is rejected without burning the token', async () => {
    const { data } = await registerAndLogin(app);
    outbox.length = 0;
    const c = createClient(app);
    await c.post('/api/auth/forgot-password', { email: data.email });
    const token = tokenFrom(lastMail(data.email));
    assert.equal((await c.post('/api/auth/reset-password', { token, password: 'short' })).status, 422);
    assert.equal((await c.post('/api/auth/reset-password', { token, password: 'a-strong-new-passphrase' })).status, 200);
  });

  test('expired reset tokens are rejected', async () => {
    const { data } = await registerAndLogin(app);
    outbox.length = 0;
    const c = createClient(app);
    await c.post('/api/auth/forgot-password', { email: data.email });
    const token = tokenFrom(lastMail(data.email));
    await pool.query("UPDATE auth_tokens SET expires_at = now() - interval '1 second'");
    const res = await c.post('/api/auth/reset-password', { token, password: 'a-strong-new-passphrase' });
    assert.equal(res.status, 400);
    assert.equal(res.body.error.code, 'INVALID_TOKEN');
  });

  test('requesting a new link invalidates the previous one', async () => {
    const { data } = await registerAndLogin(app);
    outbox.length = 0;
    const c = createClient(app);
    await c.post('/api/auth/forgot-password', { email: data.email });
    const first = tokenFrom(lastMail(data.email));
    await c.post('/api/auth/forgot-password', { email: data.email });
    const second = tokenFrom(lastMail(data.email));
    assert.notEqual(first, second);
    assert.equal((await c.post('/api/auth/reset-password', { token: first, password: 'a-strong-new-passphrase' })).status, 400);
    assert.equal((await c.post('/api/auth/reset-password', { token: second, password: 'a-strong-new-passphrase' })).status, 200);
  });
});
