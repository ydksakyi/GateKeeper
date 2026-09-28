import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import { config } from '../config/index.js';
import { pool } from '../db/pool.js';

export function createSessionMiddleware() {
  const PgStore = connectPgSimple(session);
  const store = new PgStore({
    pool,
    tableName: 'session',
    createTableIfMissing: false, // schema is managed by db/schema.sql
    pruneSessionInterval: config.isTest ? false : 15 * 60, // seconds; deletes expired rows
  });

  return session({
    name: config.cookie.name,
    secret: config.session.secrets, // array supports secret rotation
    store,
    resave: false,
    saveUninitialized: false, // no cookie or DB row until something is stored
    rolling: true, // idle timeout: every response extends the session
    unset: 'destroy',
    cookie: {
      httpOnly: true, // not readable from JavaScript
      secure: config.cookie.secure, // HTTPS only
      sameSite: config.cookie.sameSite,
      path: '/',
      maxAge: config.session.idleMs,
    },
  });
}
