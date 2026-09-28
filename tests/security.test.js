import './helpers/env.js';
import { test, describe, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { config } from '../src/config/index.js';
import { pool } from '../src/db/pool.js';
import { setupDb, resetDb, closeDb } from './helpers/db.js';
import { PASSWORD, createClient, registerAndLogin, register, patchConfig } from './helpers/client.js';

const app = createApp();

before(setupDb);
beforeEach(resetDb);
after(closeDb);

describe('CSRF and request hygiene', () => {
  test('state-changing requests without a CSRF token are rejected', async () => {
    const { data } = await registerAndLogin(app);
    const res = await request(app).post('/api/auth/login').send({ email: data.email, password: data.password });
    assert.equal(res.status, 403);
    assert.equal(res.body.error.code, 'CSRF_INVALID');
  });

  test('a wrong CSRF token is rejected, even with a valid session', async () => {
    const { client } = await registerAndLogin(app);
    const res = await client.agent.patch('/api/account').set('X-CSRF-Token', 'x'.repeat(43)).send({ name: 'Ama Serwaa' });
    assert.equal(res.status, 403);
  });

  test('a CSRF token from one session does not work in another', async () => {
    const a = createClient(app);
    const tokenA = (await a.agent.get('/api/auth/csrf')).body.csrfToken;
    const b = createClient(app);
    await b.agent.get('/api/auth/csrf');
    const res = await b.agent.post('/api/auth/login').set('X-CSRF-Token', tokenA).send({ email: 'a@b.co', password: 'whatever-it-is' });
    assert.equal(res.status, 403);
  });

  test('a foreign Origin header is rejected even with a valid token', async () => {
    const client = createClient(app);
    const token = (await client.agent.get('/api/auth/csrf')).body.csrfToken;
    const res = await client.agent.post('/api/auth/login').set('X-CSRF-Token', token).set('Origin', 'https://evil.example').send({ email: 'a@b.co', password: 'whatever-it-is' });
    assert.equal(res.status, 403);
    assert.equal(res.body.error.code, 'ORIGIN_NOT_ALLOWED');
  });

  test('the app\'s own Origin is accepted', async () => {
    const client = createClient(app);
    const token = (await client.agent.get('/api/auth/csrf')).body.csrfToken;
    const res = await client.agent.post('/api/auth/login').set('X-CSRF-Token', token).set('Origin', config.appUrl.origin).send({ email: 'a@b.co', password: 'whatever-it-is' });
    assert.equal(res.status, 401);
  });

  test('non-JSON bodies, malformed JSON and oversized bodies are refused', async () => {
    const client = createClient(app);
    const token = (await client.agent.get('/api/auth/csrf')).body.csrfToken;
    const post = () => client.agent.post('/api/auth/register').set('X-CSRF-Token', token);

    assert.equal((await post().set('Content-Type', 'text/plain').send('email=a')).status, 415);
    const bad = await post().set('Content-Type', 'application/json').send('{"name":');
    assert.equal(bad.status, 400);
    assert.equal(bad.body.error.code, 'INVALID_JSON');
    const big = await post().send({ name: 'A'.repeat(50_000) });
    assert.equal(big.status, 413);
  });
});

describe('injection attacks', () => {
  test('SQL injection payloads do not authenticate or damage the database', async () => {
    const { data } = await registerAndLogin(app);
    const attacker = createClient(app);
    const payloads = ["' OR '1'='1", "admin@example.com' --", "x'; DROP TABLE users; --"];

    for (const p of payloads) {
      const asEmail = await attacker.post('/api/auth/login', { email: p, password: PASSWORD });
      assert.ok([401, 422].includes(asEmail.status));
      const asPassword = await attacker.post('/api/auth/login', { email: data.email, password: p });
      assert.equal(asPassword.status, 401);
    }
    const { rows } = await pool.query('SELECT count(*)::int AS n FROM users');
    assert.equal(rows[0].n, 1);
  });

  test('stored XSS is blocked at the source: markup never reaches the database', async () => {
    const client = createClient(app);
    for (const name of ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', 'javascript:alert(1)//']) {
      const { res } = await register(client, { name });
      assert.equal(res.status, 422);
    }
    assert.equal((await pool.query('SELECT 1 FROM users')).rowCount, 0);
  });
});

describe('headers, CORS and cookies', () => {
  test('security headers are present and X-Powered-By is hidden', async () => {
    const res = await request(app).get('/api/health');
    assert.equal(res.headers['x-powered-by'], undefined);
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.equal(res.headers['cache-control'], 'no-store');
    assert.match(res.headers['content-security-policy'], /script-src 'self'/);
    assert.match(res.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.match(res.headers['content-type'], /application\/json/);
  });

  test('the frontend is served with the CSP too', async () => {
    const res = await request(app).get('/');
    assert.equal(res.status, 200);
    assert.match(res.text, /Gatekeeper/);
    assert.match(res.headers['content-security-policy'], /default-src 'self'/);
  });

  test('errors never leak stack traces or internals', async () => {
    const res = await request(app).get('/api/does-not-exist');
    assert.ok(!JSON.stringify(res.body).match(/stack|node_modules|SELECT|pg_/i));
  });

  describe('CORS allow-list', () => {
    let restore;
    let corsApp;
    before(() => {
      restore = patchConfig({ corsOrigins: ['https://app.example.com'] });
      corsApp = createApp();
    });
    after(() => restore());

    test('an allow-listed origin gets credentialed CORS access', async () => {
      const res = await request(corsApp).options('/api/auth/login')
        .set('Origin', 'https://app.example.com').set('Access-Control-Request-Method', 'POST');
      assert.equal(res.headers['access-control-allow-origin'], 'https://app.example.com');
      assert.equal(res.headers['access-control-allow-credentials'], 'true');
    });

    test('any other origin gets no CORS headers', async () => {
      const res = await request(corsApp).options('/api/auth/login')
        .set('Origin', 'https://evil.example').set('Access-Control-Request-Method', 'POST');
      assert.equal(res.headers['access-control-allow-origin'], undefined);
    });

    test('no origin is allowed by default', async () => {
      const res = await request(app).options('/api/auth/login')
        .set('Origin', 'https://app.example.com').set('Access-Control-Request-Method', 'POST');
      assert.equal(res.headers['access-control-allow-origin'], undefined);
    });
  });

  test('production cookie settings: Secure, HttpOnly, __Host- prefix, no Domain', async () => {
    const restore = patchConfig({ cookie: { name: '__Host-gk.sid', secure: true, sameSite: 'lax' }, trustProxy: 1 });
    try {
      const prodApp = createApp();
      const res = await request(prodApp).get('/api/auth/csrf').set('X-Forwarded-Proto', 'https');
      const cookie = res.headers['set-cookie'].find((c) => c.startsWith('__Host-gk.sid='));
      assert.match(cookie, /; Secure/i);
      assert.match(cookie, /HttpOnly/i);
      assert.match(cookie, /SameSite=Lax/i);
      assert.match(cookie, /Path=\//);
      assert.ok(!/Domain=/i.test(cookie));
    } finally {
      restore();
    }
  });
});

describe('rate limiting', () => {
  let restore;
  let limitedApp;
  before(() => {
    restore = patchConfig({
      rateLimit: {
        enabled: true,
        login: { windowMs: 60_000, ipLimit: 50, accountLimit: 3 },
        emailAccount: { windowMs: 60_000, limit: 2 },
        register: { windowMs: 60_000, limit: 2 },
      },
    });
    limitedApp = createApp();
  });
  after(() => restore());

  test('repeated failed logins for one account are throttled, even with the right password afterwards', async () => {
    const { data } = await registerAndLogin(limitedApp, { email: 'target@example.com' });
    const attacker = createClient(limitedApp);

    for (let i = 0; i < 3; i++) {
      assert.equal((await attacker.post('/api/auth/login', { email: data.email, password: 'wrong-guess-number-' + i })).status, 401);
    }
    const blocked = await attacker.post('/api/auth/login', { email: data.email, password: data.password });
    assert.equal(blocked.status, 429);
    assert.equal(blocked.body.error.code, 'RATE_LIMITED');

    // Other accounts are unaffected by that lockout key.
    const other = await attacker.post('/api/auth/login', { email: 'someone-else@example.com', password: 'wrong-guess-again' });
    assert.equal(other.status, 401);
  });

  test('the throttle applies equally to emails that do not exist (no enumeration signal)', async () => {
    const attacker = createClient(limitedApp);
    for (let i = 0; i < 3; i++) await attacker.post('/api/auth/login', { email: 'ghost@example.com', password: 'wrong-guess-' + i });
    assert.equal((await attacker.post('/api/auth/login', { email: 'ghost@example.com', password: 'wrong-guess-x' })).status, 429);
  });

  test('password-reset emails are limited per address to stop mail-bombing', async () => {
    const c = createClient(limitedApp);
    assert.equal((await c.post('/api/auth/forgot-password', { email: 'victim@example.com' })).status, 200);
    assert.equal((await c.post('/api/auth/forgot-password', { email: 'victim@example.com' })).status, 200);
    assert.equal((await c.post('/api/auth/forgot-password', { email: 'victim@example.com' })).status, 429);
  });

  test('registration is limited per client', async () => {
    const c = createClient(limitedApp);
    await register(c);
    await register(c);
    const { res } = await register(c);
    assert.equal(res.status, 429);
  });
});
