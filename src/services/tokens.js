import crypto from 'node:crypto';
import * as tokenDb from '../db/tokens.js';

// 32 random bytes -> 43 base64url characters. Only the SHA-256 hash is persisted.
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

export const hashToken = (token) =>
	crypto.createHash('sha256').update(token).digest('hex');
export const isWellFormedToken = (token) =>
	typeof token === 'string' && TOKEN_RE.test(token);

export async function issueToken(userId, purpose, ttlMs) {
	const token = crypto.randomBytes(32).toString('base64url');
	await tokenDb.replaceToken({
		userId,
		purpose,
		tokenHash: hashToken(token),
		expiresAt: new Date(Date.now() + ttlMs),
	});
	return token;
}

// Returns the user id if the token is valid, unexpired and unused (and burns it), else null.
export async function consumeToken(db, token, purpose) {
	if (!isWellFormedToken(token)) return null;
	return tokenDb.consume(db, { tokenHash: hashToken(token), purpose });
}
