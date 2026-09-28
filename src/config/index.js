// Central, validated configuration. Fails fast at startup on unsafe or missing settings.
// The exported object is intentionally a plain (mutable) object so tests can patch it.
import 'dotenv/config';

const env = process.env;
const NODE_ENV = env.NODE_ENV || 'development';
const isProd = NODE_ENV === 'production';
const isTest = NODE_ENV === 'test';

const fail = (msg) => {
	throw new Error(`[config] ${msg}`);
};
const str = (name, def) =>
	env[name] !== undefined && env[name] !== '' ? env[name] : def;
const required = (name, hint = '') =>
	str(name) ?? fail(`${name} is required. ${hint}`.trim());
const int = (name, def, min = 0) => {
	const raw = str(name);
	if (raw === undefined) return def;
	const n = Number(raw);
	if (!Number.isInteger(n) || n < min)
		fail(`${name} must be an integer >= ${min}.`);
	return n;
};
const bool = (name, def) => {
	const raw = str(name);
	return raw === undefined
		? def
		: ['1', 'true', 'yes', 'on'].includes(raw.toLowerCase());
};
const list = (name) =>
	str(name, '')
		.split(',')
		.map((s) => s.trim())
		.filter(Boolean);
const oneOf = (name, allowed, def) => {
	const v = str(name, def).toLowerCase();
	if (!allowed.includes(v))
		fail(`${name} must be one of: ${allowed.join(', ')}.`);
	return v;
};

let appUrl;
try {
	appUrl = new URL(str('APP_URL', 'http://localhost:3000'));
} catch {
	fail('APP_URL must be a valid URL.');
}
if (isProd && appUrl.protocol !== 'https:')
	fail('APP_URL must use https in production.');

const secrets = required(
	'SESSION_SECRET',
	"Generate one with: node -p \"require('crypto').randomBytes(48).toString('base64url')\"",
)
	.split(',')
	.map((s) => s.trim())
	.filter(Boolean);
if (secrets.length === 0 || secrets.some((s) => s.length < 32)) {
	fail('Every SESSION_SECRET must be at least 32 characters.');
}

const secureCookie = bool('COOKIE_SECURE', isProd);
if (isProd && !secureCookie) fail('COOKIE_SECURE must be true in production.');

const corsOrigins = list('CORS_ORIGINS');
for (const o of corsOrigins) {
	let ok = false;
	try {
		ok = new URL(o).origin === o;
	} catch {
		/* handled below */
	}
	if (!ok)
		fail(
			`CORS_ORIGINS entry "${o}" must be a bare origin such as https://app.example.com.`,
		);
}

function parseTrustProxy() {
	const raw = str('TRUST_PROXY', '0');
	if (raw === 'false' || raw === '0') return false;
	if (/^\d+$/.test(raw)) return Number(raw);
	if (raw === 'true')
		fail(
			'TRUST_PROXY=true trusts every hop and lets clients spoof their IP. Use a hop count (e.g. 1).',
		);
	return raw; // e.g. "loopback" or a subnet list understood by Express
}

const argon2 = {
	memoryCost: int('ARGON2_MEMORY_KIB', 19456, 8),
	timeCost: int('ARGON2_TIME_COST', 2, 2),
	parallelism: 1,
};
if (isProd && (argon2.memoryCost < 19456 || argon2.timeCost < 2)) {
	fail(
		'Production requires ARGON2_MEMORY_KIB >= 19456 and ARGON2_TIME_COST >= 2 (OWASP minimum).',
	);
}

const emailTransport = isTest
	? 'memory'
	: oneOf('EMAIL_TRANSPORT', ['console', 'smtp'], isProd ? 'smtp' : 'console');
if (isProd && emailTransport !== 'smtp')
	fail('EMAIL_TRANSPORT must be smtp in production.');
if (emailTransport === 'smtp' && !str('SMTP_HOST'))
	fail('SMTP_HOST is required when EMAIL_TRANSPORT=smtp.');

const DAY = 24 * 60 * 60 * 1000;
const MIN = 60 * 1000;
const HOUR = 60 * MIN;

export const config = {
	env: NODE_ENV,
	isProd,
	isTest,
	port: int('PORT', 3000, 1),
	appUrl,
	trustProxy: parseTrustProxy(),
	corsOrigins,

	db: {
		url: required('DATABASE_URL'),
		ssl: bool('DATABASE_SSL', false),
		poolMax: int('DATABASE_POOL_MAX', 10, 1),
	},

	session: {
		secrets,
		idleMs: int('SESSION_IDLE_MINUTES', 120, 1) * MIN,
		rememberMs: int('SESSION_REMEMBER_DAYS', 14, 1) * DAY,
		absoluteMs: int('SESSION_ABSOLUTE_DAYS', 30, 1) * DAY,
	},

	cookie: {
		// The __Host- prefix makes browsers reject cookies that are not Secure, have a Domain, or a non-root Path.
		name: secureCookie ? '__Host-gk.sid' : 'gk.sid',
		secure: secureCookie,
		sameSite: oneOf('COOKIE_SAMESITE', ['lax', 'strict'], 'lax'),
	},

	argon2,

	emailVerification: oneOf(
		'EMAIL_VERIFICATION',
		['off', 'optional', 'required'],
		'optional',
	),
	tokens: {
		resetTtlMs: int('RESET_TOKEN_MINUTES', 30, 1) * MIN,
		verifyTtlMs: int('VERIFY_TOKEN_HOURS', 24, 1) * HOUR,
	},

	email: {
		transport: emailTransport,
		from: str('EMAIL_FROM', 'Gatekeeper <no-reply@localhost>'),
		smtp: {
			host: str('SMTP_HOST'),
			port: int('SMTP_PORT', 587, 1),
			secure: bool('SMTP_SECURE', false),
			user: str('SMTP_USER'),
			pass: str('SMTP_PASS'),
		},
	},

	rateLimit: {
		enabled: bool('RATE_LIMIT_ENABLED', !isTest),
		global: { windowMs: 15 * MIN, limit: int('RL_GLOBAL_LIMIT', 300, 1) },
		login: {
			windowMs: 15 * MIN,
			ipLimit: int('RL_LOGIN_IP_LIMIT', 20, 1),
			accountLimit: int('RL_LOGIN_ACCOUNT_LIMIT', 10, 1),
		},
		register: { windowMs: HOUR, limit: int('RL_REGISTER_LIMIT', 10, 1) },
		passwordReset: { windowMs: HOUR, limit: int('RL_RESET_LIMIT', 5, 1) },
		emailAccount: {
			windowMs: HOUR,
			limit: int('RL_EMAIL_ACCOUNT_LIMIT', 3, 1),
		},
		verification: { windowMs: HOUR, limit: int('RL_VERIFY_LIMIT', 10, 1) },
	},
};
