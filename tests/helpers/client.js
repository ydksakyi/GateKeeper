import assert from 'node:assert/strict';
import request from 'supertest';
import { config } from '../../src/config/index.js';
import { outbox } from '../../src/services/email.js';
import { pool } from '../../src/db/pool.js';

export const PASSWORD = 'correct-horse-battery';
let counter = 0;
export const uniqueEmail = () => `user${++counter}@example.com`;

// Temporarily patch top-level config sections (shallow merge per section). Returns a restore function.
export function patchConfig(patch) {
  const saved = {};
  for (const [key, value] of Object.entries(patch)) {
    saved[key] = config[key];
    config[key] = value !== null && typeof value === 'object' && !Array.isArray(value) && !(value instanceof URL) ? { ...config[key], ...value } : value;
  }
  return () => Object.assign(config, saved);
}

// A browser-like client: keeps cookies and handles the CSRF token the way public/js/api.js does.
export function createClient(app) {
  const agent = request.agent(app);
  let csrf = null;

  async function send(method, url, body) {
    if (!csrf) csrf = (await agent.get('/api/auth/csrf')).body.csrfToken;
    const req = agent[method](url).set('X-CSRF-Token', csrf);
    if (body !== undefined) req.send(body);
    const res = await req;
    if (res.body?.csrfToken) csrf = res.body.csrfToken;
    if (url.endsWith('/logout')) csrf = null;
    return res;
  }

  return {
    agent,
    get: (url) => agent.get(url),
    post: (url, body) => send('post', url, body),
    patch: (url, body) => send('patch', url, body),
    setCsrf: (token) => { csrf = token; },
  };
}

export async function register(client, overrides = {}) {
  const data = { name: 'Ama Serwaa', email: uniqueEmail(), password: PASSWORD, ...overrides };
  const res = await client.post('/api/auth/register', data);
  return { res, data };
}

export async function registerAndLogin(app, overrides = {}) {
  const client = createClient(app);
  const { data } = await register(client, overrides);
  const res = await client.post('/api/auth/login', { email: data.email, password: data.password });
  assert.equal(res.status, 200, `login failed: ${JSON.stringify(res.body)}`);
  return { client, data, res };
}

export const makeAdmin = (email) => pool.query("UPDATE users SET role = 'admin' WHERE email = $1", [email]);
export const lastMail = (to) => [...outbox].reverse().find((m) => m.to === to);
export const tokenFrom = (mail) => mail.text.match(/token=([A-Za-z0-9_-]{43})/)[1];

// Extracts "name=value" of the session cookie from a response, for replay attacks.
export function sessionCookie(res) {
  const raw = (res.headers['set-cookie'] ?? []).find((c) => c.startsWith(`${config.cookie.name}=`));
  return raw ? raw.split(';')[0] : null;
}
