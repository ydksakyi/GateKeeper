// Applies db/schema.sql. Uses only DATABASE_URL (or TEST_DATABASE_URL with --test),
// so it does not need the rest of the app configuration.
import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const useTest = process.argv.includes('--test');
const url = useTest ? process.env.TEST_DATABASE_URL : process.env.DATABASE_URL;
if (!url) {
	console.error(
		`${useTest ? 'TEST_DATABASE_URL' : 'DATABASE_URL'} is not set.`,
	);
	process.exit(1);
}

const schema = fs.readFileSync(
	path.join(
		path.dirname(fileURLToPath(import.meta.url)),
		'..',
		'db',
		'schema.sql',
	),
	'utf8',
);
const ssl =
	process.env.DATABASE_SSL === 'true'
		? { rejectUnauthorized: true }
		: undefined;
const client = new pg.Client({ connectionString: url, ssl });

try {
	await client.connect();
	await client.query(schema);
	console.log('Schema applied.');
} catch (err) {
	console.error('Migration failed:', err.message);
	process.exitCode = 1;
} finally {
	await client.end();
}
