import crypto from 'node:crypto';
import argon2 from 'argon2';
import { config } from '../config/index.js';

const options = { type: argon2.argon2id, ...config.argon2 };

export const hashPassword = (password) => argon2.hash(password, options);

export async function verifyPassword(hash, password) {
	try {
		return await argon2.verify(hash, password);
	} catch {
		return false; // malformed hash etc. must never reveal anything
	}
}

// True when stored parameters are weaker than the current configuration.
export const needsRehash = (hash) => argon2.needsRehash(hash, options);

// Burn the same CPU for unknown emails as for real ones so response time does not reveal
// whether an account exists.
let dummyHash;
export async function verifyAgainstDummy(password) {
	dummyHash ??= hashPassword(crypto.randomBytes(16).toString('hex'));
	await verifyPassword(await dummyHash, password);
}
