// MUST be the first import of every test file: it prepares process.env before the app loads.
import 'dotenv/config';

const testDb = process.env.TEST_DATABASE_URL;
if (!testDb) throw new Error('Set TEST_DATABASE_URL (see .env.example) to run the tests.');
if (!/test/i.test(new URL(testDb).pathname)) {
  throw new Error('Refusing to run: the test database name must contain "test" because tests wipe tables.');
}

Object.assign(process.env, {
  NODE_ENV: 'test',
  DATABASE_URL: testDb,
  DATABASE_SSL: 'false',
  SESSION_SECRET: 'test-only-secret-that-is-at-least-32-characters-long',
  APP_URL: 'http://localhost:3000',
  COOKIE_SECURE: 'false',
  COOKIE_SAMESITE: 'lax',
  TRUST_PROXY: '0',
  CORS_ORIGINS: '',
  EMAIL_VERIFICATION: 'optional',
  RATE_LIMIT_ENABLED: 'false',
  ARGON2_MEMORY_KIB: '1024', // tiny cost so the suite is fast; production enforces the real minimums
  ARGON2_TIME_COST: '2',
});
