// Server-side validation and sanitisation. This is the authority; the browser copy in
// public/js/validators.js exists only for faster feedback and is never trusted.
// Each validateX returns { value } on success or { errors: { field: message } }.

const isObject = (v) =>
	v !== null && typeof v === 'object' && !Array.isArray(v);
const body = (b) => (isObject(b) ? b : {});

const CONTROL_CHARS =
	/[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2028-\u202E\u2060\uFEFF]/g;

// Unicode-normalise, collapse whitespace, strip control/invisible characters.
export function sanitizeText(value) {
	if (typeof value !== 'string') return '';
	return value
		.normalize('NFKC')
		.replace(/\s+/g, ' ')
		.replace(CONTROL_CHARS, '')
		.trim();
}

export function sanitizeName(value) {
	return sanitizeText(value);
}

export function sanitizeEmail(value) {
	return typeof value === 'string'
		? value.normalize('NFKC').trim().toLowerCase()
		: '';
}

// Allow-list, not block-list: letters, marks, spaces, and . ' ’ - only. No angle brackets,
// digits or symbols, so a name can never carry markup even if some output path forgets to escape.
const NAME_RE = /^[\p{L}\p{M}][\p{L}\p{M} .'’-]{1,79}$/u;
export const isValidName = (name) => NAME_RE.test(name);

const EMAIL_RE =
	/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
export const isValidEmail = (email) =>
	typeof email === 'string' &&
	email.length <= 254 &&
	email.indexOf('@') <= 64 &&
	EMAIL_RE.test(email);

const COMMON_PASSWORDS = new Set([
	'password123',
	'password1234',
	'password12345',
	'1234567890',
	'0123456789',
	'12345678910',
	'1234567890a',
	'qwertyuiop',
	'qwerty12345',
	'qwertyuiop1',
	'iloveyou123',
	'letmein1234',
	'welcome1234',
	'adminadmin1',
	'administrator',
	'passw0rd123',
	'changeme123',
	'abcdefghij',
	'ghana12345',
	'akwaaba123',
	'knust12345',
	'kumasi12345',
]);

// Length-first policy (NIST 800-63B style): no composition rules, but block trivially guessable values.
export function checkPassword(password, { email } = {}) {
	if (typeof password !== 'string' || password.length === 0)
		return 'Password is required.';
	if (password.length < 10) return 'Use at least 10 characters.';
	if (password.length > 128) return 'Use no more than 128 characters.';
	if (/^(.)\1+$/su.test(password)) return 'Password is too repetitive.';
	if (COMMON_PASSWORDS.has(password.toLowerCase()))
		return 'That password is too common.';
	if (email && password.toLowerCase() === email)
		return 'Password must not be your email address.';
	return null;
}

export const isUuid = (v) =>
	typeof v === 'string' &&
	/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);

const result = (errors, value) =>
	Object.keys(errors).length ? { errors } : { value };

export function validateRegistration(input) {
	const b = body(input);
	const name = sanitizeName(b.name);
	const email = sanitizeEmail(b.email);
	const errors = {};
	if (!isValidName(name))
		errors.name =
			'Enter your name using letters, spaces, hyphens or apostrophes (2–80 characters).';
	if (!isValidEmail(email)) errors.email = 'Enter a valid email address.';
	const pw = checkPassword(b.password, { email });
	if (pw) errors.password = pw;
	// Only these three fields are ever read: a client cannot set role, verification status, etc.
	return result(errors, { name, email, password: b.password });
}

export function validateLogin(input) {
	const b = body(input);
	const email = sanitizeEmail(b.email);
	const errors = {};
	if (!isValidEmail(email)) errors.email = 'Enter a valid email address.';
	if (
		typeof b.password !== 'string' ||
		b.password.length === 0 ||
		b.password.length > 128
	) {
		errors.password = 'Enter your password.';
	}
	return result(errors, {
		email,
		password: b.password,
		remember: b.remember === true,
	});
}

export function validateEmailOnly(input) {
	const email = sanitizeEmail(body(input).email);
	return result(
		isValidEmail(email) ? {} : { email: 'Enter a valid email address.' },
		{ email },
	);
}

export function validateToken(input) {
	const token = body(input).token;
	return result(
		typeof token === 'string' && token.length > 0 && token.length <= 200
			? {}
			: { token: 'Token is required.' },
		{ token },
	);
}

export function validateResetPassword(input) {
	const b = body(input);
	const errors = {};
	if (
		typeof b.token !== 'string' ||
		b.token.length === 0 ||
		b.token.length > 200
	)
		errors.token = 'Token is required.';
	const pw = checkPassword(b.password);
	if (pw) errors.password = pw;
	return result(errors, { token: b.token, password: b.password });
}

export function validateRoleChange(input) {
	const role = body(input).role;
	return result(
		role === 'user' || role === 'admin'
			? {}
			: { role: 'Role must be "user" or "admin".' },
		{ role },
	);
}

export function validateProfile(input) {
	const name = sanitizeName(body(input).name);
	return result(
		isValidName(name)
			? {}
			: {
					name: 'Enter your name using letters, spaces, hyphens or apostrophes (2–80 characters).',
				},
		{ name },
	);
}

export function parsePagination(query) {
	const num = (v, def, min, max) => {
		const n = Number.parseInt(v, 10);
		return Number.isInteger(n) ? Math.min(Math.max(n, min), max) : def;
	};
	return {
		page: num(query?.page, 1, 1, 1_000_000),
		pageSize: num(query?.pageSize, 25, 1, 100),
	};
}
