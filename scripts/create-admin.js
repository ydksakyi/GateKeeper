// Creates an admin, or promotes an existing user to admin.
//   npm run create-admin -- you@example.com "Your Name"
// The password is read from a hidden prompt (or ADMIN_PASSWORD for automation).
import readline from 'node:readline';
import { pool } from '../src/db/pool.js';
import * as users from '../src/db/users.js';
import { hashPassword } from '../src/services/password.js';
import {
	sanitizeEmail,
	sanitizeText,
	isValidEmail,
	isValidName,
	checkPassword,
} from '../src/validators/index.js';

function promptHidden(question) {
	return new Promise((resolve) => {
		const rl = readline.createInterface({
			input: process.stdin,
			output: process.stdout,
		});
		process.stdout.write(question);
		rl._writeToOutput = () => {}; // do not echo keystrokes
		rl.question('', (answer) => {
			rl.close();
			process.stdout.write('\n');
			resolve(answer);
		});
	});
}

async function main() {
	const [, , rawEmail, ...nameParts] = process.argv;
	const email = sanitizeEmail(rawEmail);
	const name = sanitizeText(nameParts.join(' ')) || 'Administrator';
	if (!isValidEmail(email))
		throw new Error('Usage: npm run create-admin -- <email> ["Full Name"]');

	const existing = await users.findCredentialsByEmail(email);
	if (existing) {
		await pool.query(
			"UPDATE users SET role = 'admin', updated_at = now() WHERE id = $1",
			[existing.id],
		);
		console.log(`Promoted ${email} to admin.`);
		return;
	}

	if (!isValidName(name))
		throw new Error('Name contains unsupported characters.');
	const password =
		process.env.ADMIN_PASSWORD || (await promptHidden('Password: '));
	const problem = checkPassword(password, { email });
	if (problem) throw new Error(problem);

	await users.createUser({
		name,
		email,
		passwordHash: await hashPassword(password),
		role: 'admin',
		verified: true,
	});
	console.log(`Created admin ${email}.`);
}

try {
	await main();
} catch (err) {
	console.error(err.message);
	process.exitCode = 1;
} finally {
	await pool.end();
}
