import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { config } from './config/index.js';
import {
	securityHeaders,
	corsMiddleware,
	noStore,
} from './middleware/security.js';
import { originCheck, csrfProtection } from './middleware/csrf.js';
import { requireJson } from './middleware/requireJson.js';
import { createSessionMiddleware } from './middleware/session.js';
import { authenticate } from './middleware/authenticate.js';
import { buildRateLimiters } from './middleware/rateLimit.js';
import { notFound, errorHandler } from './middleware/errorHandler.js';
import { apiRouter } from './routes/index.js';

const publicDir = path.join(
	path.dirname(fileURLToPath(import.meta.url)),
	'..',
	'public',
);

export function createApp() {
	const app = express();
	const limiters = buildRateLimiters(config.rateLimit);

	app.set('trust proxy', config.trustProxy);
	app.disable('x-powered-by');
	app.use(securityHeaders());
	app.use(
		express.static(publicDir, {
			dotfiles: 'ignore',
			maxAge: config.isProd ? '1h' : 0,
		}),
	);

	// Order matters: cheap rejections first, session/auth next, CSRF before any handler runs.
	app.use(
		'/api',
		noStore,
		corsMiddleware(),
		originCheck(),
		limiters.global,
		requireJson,
		express.json({ limit: '10kb', strict: true }),
		createSessionMiddleware(),
		authenticate,
		csrfProtection,
		apiRouter(limiters),
	);

	app.use(notFound);
	app.use(errorHandler);
	return app;
}
