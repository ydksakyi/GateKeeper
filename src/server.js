import { config } from './config/index.js';
import { createApp } from './app.js';
import { pool } from './db/pool.js';

try {
	await pool.query('SELECT 1'); // fail fast if the database is unreachable
} catch (err) {
	console.error('Cannot connect to PostgreSQL:', err.message);
	process.exit(1);
}

const server = createApp().listen(config.port, () => {
	console.log(
		`Gatekeeper listening on ${config.appUrl.origin} (port ${config.port}, ${config.env})`,
	);
});

async function shutdown(signal) {
	console.log(`${signal} received, shutting down...`);
	server.close(async () => {
		await pool.end();
		process.exit(0);
	});
	setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (reason) =>
	console.error('Unhandled rejection:', reason),
);
