// Browser-side validation for fast feedback only. The server re-validates everything
// (src/validators/index.js) and is the only authority. Keep the rules in sync.

const CONTROL =
	/[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2028-\u202E\u2060\uFEFF]/g;

export const sanitizeName = (v) =>
	String(v ?? '')
		.normalize('NFKC')
		.replace(/\s+/g, ' ')
		.replace(CONTROL, '')
		.trim();
export const sanitizeEmail = (v) =>
	String(v ?? '')
		.normalize('NFKC')
		.trim()
		.toLowerCase();

const NAME_RE = /^[\p{L}\p{M}][\p{L}\p{M} .'’-]{1,79}$/u;
const EMAIL_RE =
	/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

export const validateName = (name) =>
	NAME_RE.test(name)
		? null
		: 'Enter your name using letters, spaces, hyphens or apostrophes (2–80 characters).';

export const validateEmail = (email) =>
	email.length <= 254 && email.indexOf('@') <= 64 && EMAIL_RE.test(email)
		? null
		: 'Enter a valid email address.';

export function validatePassword(password, email = '') {
	if (!password) return 'Password is required.';
	if (password.length < 10) return 'Use at least 10 characters.';
	if (password.length > 128) return 'Use no more than 128 characters.';
	if (/^(.)\1+$/su.test(password)) return 'Password is too repetitive.';
	if (email && password.toLowerCase() === email)
		return 'Password must not be your email address.';
	return null;
}
