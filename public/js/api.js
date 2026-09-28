// Thin fetch wrapper: same-origin cookies, JSON, and automatic CSRF-token handling.
let csrfToken = null;

export class ApiError extends Error {
	constructor(status, body) {
		super(body?.error?.message || 'Something went wrong. Please try again.');
		this.status = status;
		this.code = body?.error?.code;
		this.details = body?.error?.details;
	}
}

async function loadCsrf() {
	const res = await fetch('/api/auth/csrf', { credentials: 'same-origin' });
	csrfToken = (await res.json()).csrfToken;
}

async function request(method, path, body, canRetry = true) {
	const headers = { Accept: 'application/json' };
	if (method !== 'GET') {
		if (!csrfToken) await loadCsrf();
		headers['X-CSRF-Token'] = csrfToken;
	}
	if (body !== undefined) headers['Content-Type'] = 'application/json';

	const res = await fetch(path, {
		method,
		headers,
		credentials: 'same-origin',
		body: body === undefined ? undefined : JSON.stringify(body),
	});
	const data = res.status === 204 ? null : await res.json().catch(() => null);

	if (!res.ok) {
		if (
			res.status === 403 &&
			data?.error?.code === 'CSRF_INVALID' &&
			canRetry
		) {
			csrfToken = null; // session changed underneath us; fetch a fresh token once
			return request(method, path, body, false);
		}
		throw new ApiError(res.status, data);
	}
	if (data?.csrfToken) csrfToken = data.csrfToken; // login issues a token for the new session
	return data;
}

export const api = {
	me: () => request('GET', '/api/auth/me'),
	register: (b) => request('POST', '/api/auth/register', b),
	login: (b) => request('POST', '/api/auth/login', b),
	logout: async () => {
		await request('POST', '/api/auth/logout');
		csrfToken = null;
	},
	forgotPassword: (email) =>
		request('POST', '/api/auth/forgot-password', { email }),
	resetPassword: (b) => request('POST', '/api/auth/reset-password', b),
	verifyEmail: (token) => request('POST', '/api/auth/verify-email', { token }),
	resendVerification: (email) =>
		request('POST', '/api/auth/resend-verification', { email }),
	updateName: (name) => request('PATCH', '/api/account', { name }),
	listUsers: () => request('GET', '/api/admin/users?pageSize=100'),
	setRole: (id, role) =>
		request('PATCH', `/api/admin/users/${encodeURIComponent(id)}/role`, {
			role,
		}),
};
