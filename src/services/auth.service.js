import { config } from '../config/index.js';
import { pool, withTransaction } from '../db/pool.js';
import * as users from '../db/users.js';
import { AppError } from '../utils/AppError.js';
import {
	hashPassword,
	verifyPassword,
	verifyAgainstDummy,
	needsRehash,
} from './password.js';
import { issueToken, consumeToken, isWellFormedToken } from './tokens.js';
import { sendInBackground, templates } from './email.js';

const invalidCredentials = () =>
	new AppError(401, 'INVALID_CREDENTIALS', 'Invalid email or password.');
const invalidToken = () =>
	new AppError(400, 'INVALID_TOKEN', 'This link is invalid or has expired.');

// Registration never reveals whether the email was already taken: both outcomes return the same
// response. The hash is computed either way so timing is similar too.
export async function register({ name, email, password }) {
	const passwordHash = await hashPassword(password);
	const user = await users.createUser({ name, email, passwordHash });

	if (!user) {
		sendInBackground(templates.alreadyRegistered({ to: email }));
		return;
	}
	if (config.emailVerification !== 'off') {
		const token = await issueToken(
			user.id,
			'email_verify',
			config.tokens.verifyTtlMs,
		);
		sendInBackground(
			templates.verifyEmail({ to: email, name: user.name, token }),
		);
	}
}

export async function verifyCredentials({ email, password }) {
	const row = await users.findCredentialsByEmail(email);
	if (!row) {
		await verifyAgainstDummy(password);
		throw invalidCredentials();
	}
	if (!(await verifyPassword(row.password_hash, password)))
		throw invalidCredentials();

	// Checked only after the password is correct, so this cannot be used to probe for accounts.
	if (config.emailVerification === 'required' && !row.email_verified_at) {
		throw new AppError(
			403,
			'EMAIL_NOT_VERIFIED',
			'Please verify your email address before signing in.',
		);
	}

	// Transparently upgrade hashes created with weaker parameters.
	if (needsRehash(row.password_hash)) {
		try {
			await users.updatePasswordHash(
				pool,
				row.id,
				await hashPassword(password),
			);
		} catch (err) {
			console.error('Password rehash failed:', err.message);
		}
	}
	return users.toPublicUser(row);
}

export async function requestPasswordReset(email) {
	const row = await users.findCredentialsByEmail(email);
	if (!row) return;
	const token = await issueToken(
		row.id,
		'password_reset',
		config.tokens.resetTtlMs,
	);
	sendInBackground(
		templates.passwordReset({ to: email, name: row.name, token }),
	);
}

export async function resetPassword({ token, password }) {
	if (!isWellFormedToken(token)) throw invalidToken(); // cheap rejection before the expensive hash
	const passwordHash = await hashPassword(password);

	const userId = await withTransaction(async (tx) => {
		const id = await consumeToken(tx, token, 'password_reset');
		if (!id) return null;
		await users.updatePasswordHash(tx, id, passwordHash);
		await users.markEmailVerified(tx, id); // following an emailed link proves control of the address
		await users.deleteSessionsForUser(tx, id); // sign out every device
		return id;
	});
	if (!userId) throw invalidToken();
}

export async function verifyEmail(token) {
	const userId = await withTransaction(async (tx) => {
		const id = await consumeToken(tx, token, 'email_verify');
		if (id) await users.markEmailVerified(tx, id);
		return id;
	});
	if (!userId) throw invalidToken();
}

export async function resendVerification(email) {
	if (config.emailVerification === 'off') return;
	const row = await users.findCredentialsByEmail(email);
	if (!row || row.email_verified_at) return;
	const token = await issueToken(
		row.id,
		'email_verify',
		config.tokens.verifyTtlMs,
	);
	sendInBackground(templates.verifyEmail({ to: email, name: row.name, token }));
}
