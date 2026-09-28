// Hash-routed single page UI. All dynamic content is inserted with textContent / text nodes
// (never innerHTML), so user-controlled values cannot become markup.
import { api, ApiError } from './api.js';
import {
	sanitizeName,
	sanitizeEmail,
	validateName,
	validateEmail,
	validatePassword,
} from './validators.js';

const root = document.getElementById('app');
const nav = document.getElementById('nav');
const state = { user: null, notice: null };

function h(tag, attrs = {}, ...children) {
	const el = document.createElement(tag);
	for (const [key, val] of Object.entries(attrs ?? {})) {
		if (val === false || val == null) continue;
		if (key.startsWith('on')) el.addEventListener(key.slice(2), val);
		else if (key === 'class') el.className = val;
		else el.setAttribute(key, val === true ? '' : val);
	}
	for (const child of children.flat())
		el.append(child instanceof Node ? child : String(child ?? ''));
	return el;
}

function render(...nodes) {
	root.replaceChildren(...nodes);
	root.focus();
}

const banner = (text, ok = false) =>
	h(
		'p',
		{ class: ok ? 'alert ok' : 'alert', role: ok ? 'status' : 'alert' },
		text,
	);

// A labelled input with an inline error slot wired up for assistive technology.
function field({ id, label, type = 'text', autocomplete, hint }) {
	const input = h('input', {
		id,
		name: id,
		type,
		autocomplete,
		required: true,
		'aria-describedby': `${id}-msg`,
	});
	const msg = h('p', { class: 'error', id: `${id}-msg` });
	const wrap = h(
		'div',
		{ class: 'field' },
		h('label', { for: id }, label),
		input,
		hint ? h('span', { class: 'hint' }, hint) : null,
		msg,
	);
	const setError = (text) => {
		msg.textContent = text ?? '';
		input.setAttribute('aria-invalid', text ? 'true' : 'false');
	};
	return { wrap, input, setError };
}

function parseRoute() {
	const [path, query = ''] = location.hash.replace(/^#/, '').split('?');
	return { path: path || '/', params: new URLSearchParams(query) };
}
const go = (path) => {
	if (location.hash === `#${path}`) route();
	else location.hash = path;
};

function renderNav() {
	const items = [];
	if (state.user) {
		items.push(h('a', { href: '#/dashboard' }, 'Account'));
		if (state.user.role === 'admin')
			items.push(h('a', { href: '#/admin' }, 'Users'));
		items.push(
			h(
				'button',
				{ class: 'secondary', type: 'button', onclick: signOut },
				'Sign out',
			),
		);
	} else {
		items.push(
			h('a', { href: '#/login' }, 'Sign in'),
			h('a', { href: '#/register' }, 'Create account'),
		);
	}
	nav.replaceChildren(...items);
}

async function signOut() {
	try {
		await api.logout();
	} catch {
		/* session may already be gone */
	}
	state.user = null;
	state.notice = 'You have been signed out.';
	go('/login');
}

function submitHandler(form, button, action) {
	form.addEventListener('submit', async (event) => {
		event.preventDefault();
		button.disabled = true;
		try {
			await action();
		} finally {
			button.disabled = false;
		}
	});
}

// ---- views ---------------------------------------------------------------

function loginView() {
	const email = field({
		id: 'email',
		label: 'Email',
		type: 'email',
		autocomplete: 'email',
	});
	const password = field({
		id: 'password',
		label: 'Password',
		type: 'password',
		autocomplete: 'current-password',
	});
	const remember = h('input', { id: 'remember', type: 'checkbox' });
	const status = h('div');
	const button = h('button', { type: 'submit' }, 'Sign in');
	const form = h(
		'form',
		{ novalidate: true },
		email.wrap,
		password.wrap,
		h(
			'label',
			{ class: 'check', for: 'remember' },
			remember,
			'Keep me signed in on this device',
		),
		button,
	);

	submitHandler(form, button, async () => {
		status.replaceChildren();
		const e = sanitizeEmail(email.input.value);
		const emailErr = validateEmail(e);
		email.setError(emailErr);
		password.setError(password.input.value ? null : 'Enter your password.');
		if (emailErr || !password.input.value) return;
		try {
			const { user } = await api.login({
				email: e,
				password: password.input.value,
				remember: remember.checked,
			});
			state.user = user;
			state.notice = null;
			go('/dashboard');
		} catch (err) {
			const extra =
				err.code === 'EMAIL_NOT_VERIFIED'
					? h(
							'button',
							{
								type: 'button',
								class: 'linklike',
								onclick: async () => {
									await api.resendVerification(e).catch(() => {});
									status.replaceChildren(
										banner(
											'If that account needs verification, a new link has been sent.',
											true,
										),
									);
								},
							},
							' Send a new link',
						)
					: null;
			const shown =
				err instanceof ApiError ? err.message : 'Could not reach the server.';
			status.replaceChildren(
				h('p', { class: 'alert', role: 'alert' }, shown, extra),
			);
		}
	});

	render(
		h(
			'section',
			{ class: 'panel' },
			h('h1', {}, 'Sign in'),
			state.notice ? banner(state.notice, true) : null,
			status,
			form,
			h(
				'p',
				{},
				h('a', { href: '#/forgot-password' }, 'Forgot your password?'),
			),
			h(
				'p',
				{},
				'New here? ',
				h('a', { href: '#/register' }, 'Create an account'),
			),
		),
	);
	state.notice = null;
}

function registerView() {
	const name = field({ id: 'name', label: 'Full name', autocomplete: 'name' });
	const email = field({
		id: 'email',
		label: 'Email',
		type: 'email',
		autocomplete: 'email',
	});
	const password = field({
		id: 'password',
		label: 'Password',
		type: 'password',
		autocomplete: 'new-password',
		hint: 'At least 10 characters. A few random words works well.',
	});
	const status = h('div');
	const button = h('button', { type: 'submit' }, 'Create account');
	const form = h(
		'form',
		{ novalidate: true },
		name.wrap,
		email.wrap,
		password.wrap,
		button,
	);

	submitHandler(form, button, async () => {
		status.replaceChildren();
		const n = sanitizeName(name.input.value);
		const e = sanitizeEmail(email.input.value);
		const errs = {
			name: validateName(n),
			email: validateEmail(e),
			password: validatePassword(password.input.value, e),
		};
		name.setError(errs.name);
		email.setError(errs.email);
		password.setError(errs.password);
		if (Object.values(errs).some(Boolean)) return;
		try {
			const { message } = await api.register({
				name: n,
				email: e,
				password: password.input.value,
			});
			state.notice = message;
			go('/login');
		} catch (err) {
			if (err.details) {
				name.setError(err.details.name);
				email.setError(err.details.email);
				password.setError(err.details.password);
			} else {
				status.replaceChildren(
					banner(
						err instanceof ApiError
							? err.message
							: 'Could not reach the server.',
					),
				);
			}
		}
	});

	render(
		h(
			'section',
			{ class: 'panel' },
			h('h1', {}, 'Create your account'),
			status,
			form,
			h(
				'p',
				{},
				'Already registered? ',
				h('a', { href: '#/login' }, 'Sign in'),
			),
		),
	);
}

function forgotView() {
	const email = field({
		id: 'email',
		label: 'Email',
		type: 'email',
		autocomplete: 'email',
	});
	const status = h('div');
	const button = h('button', { type: 'submit' }, 'Send reset link');
	const form = h('form', { novalidate: true }, email.wrap, button);
	submitHandler(form, button, async () => {
		const e = sanitizeEmail(email.input.value);
		const err = validateEmail(e);
		email.setError(err);
		if (err) return;
		try {
			const { message } = await api.forgotPassword(e);
			status.replaceChildren(banner(message, true));
		} catch (error) {
			status.replaceChildren(
				banner(
					error instanceof ApiError
						? error.message
						: 'Could not reach the server.',
				),
			);
		}
	});
	render(
		h(
			'section',
			{ class: 'panel' },
			h('h1', {}, 'Reset your password'),
			h(
				'p',
				{ class: 'lede' },
				'Enter your email and we will send a link that works once and expires soon.',
			),
			status,
			form,
			h('p', {}, h('a', { href: '#/login' }, 'Back to sign in')),
		),
	);
}

function resetView(params) {
	const token = params.get('token') ?? '';
	history.replaceState(null, '', '#/reset-password'); // keep the token out of the address bar and history
	const password = field({
		id: 'password',
		label: 'New password',
		type: 'password',
		autocomplete: 'new-password',
		hint: 'At least 10 characters.',
	});
	const status = h('div');
	const button = h('button', { type: 'submit' }, 'Set new password');
	const form = h('form', { novalidate: true }, password.wrap, button);
	submitHandler(form, button, async () => {
		const err = validatePassword(password.input.value);
		password.setError(err);
		if (err) return;
		try {
			const { message } = await api.resetPassword({
				token,
				password: password.input.value,
			});
			state.notice = message;
			go('/login');
		} catch (error) {
			if (error.details?.password) password.setError(error.details.password);
			else
				status.replaceChildren(
					banner(
						error instanceof ApiError
							? error.message
							: 'Could not reach the server.',
					),
				);
		}
	});
	render(
		h(
			'section',
			{ class: 'panel' },
			h('h1', {}, 'Choose a new password'),
			status,
			form,
		),
	);
}

async function verifyView(params) {
	const token = params.get('token') ?? '';
	history.replaceState(null, '', '#/verify-email');
	const box = h(
		'section',
		{ class: 'panel' },
		h('h1', {}, 'Verifying your email…'),
	);
	render(box);
	try {
		const { message } = await api.verifyEmail(token);
		if (state.user) state.user = { ...state.user, emailVerified: true };
		box.replaceChildren(
			h('h1', {}, 'Email verified'),
			banner(message, true),
			h('p', {}, h('a', { href: '#/login' }, 'Continue')),
		);
	} catch (err) {
		box.replaceChildren(
			h('h1', {}, 'Link not valid'),
			banner(
				err instanceof ApiError ? err.message : 'Could not reach the server.',
			),
			h('p', {}, 'Sign in and request a new verification link.'),
		);
	}
}

function dashboardView() {
	const u = state.user;
	const name = field({
		id: 'name',
		label: 'Display name',
		autocomplete: 'name',
	});
	name.input.value = u.name;
	const status = h('div');
	const button = h('button', { type: 'submit' }, 'Save name');
	const form = h('form', { novalidate: true }, name.wrap, button);
	submitHandler(form, button, async () => {
		const n = sanitizeName(name.input.value);
		const err = validateName(n);
		name.setError(err);
		if (err) return;
		try {
			state.user = (await api.updateName(n)).user;
			status.replaceChildren(banner('Name updated.', true));
			renderNav();
			root.querySelector('h1').textContent = `Akwaaba, ${state.user.name}`;
		} catch (error) {
			if (error.details?.name) name.setError(error.details.name);
			else
				status.replaceChildren(
					banner(
						error instanceof ApiError
							? error.message
							: 'Could not reach the server.',
					),
				);
		}
	});

	render(
		h(
			'section',
			{ class: 'panel' },
			h('h1', {}, `Akwaaba, ${u.name}`),
			h('p', { class: 'lede' }, 'You are signed in.'),
			h(
				'dl',
				{},
				h('dt', {}, 'Email'),
				h('dd', {}, u.email),
				h('dt', {}, 'Role'),
				h('dd', {}, h('span', { class: 'badge' }, u.role)),
				h('dt', {}, 'Email status'),
				h('dd', {}, u.emailVerified ? 'Verified' : 'Not verified yet'),
			),
			status,
			form,
		),
	);
}

async function adminView() {
	const box = h('section', { class: 'panel wide' }, h('h1', {}, 'Users'));
	render(box);
	try {
		const { users, total } = await api.listUsers();
		const rows = users.map((user) => {
			const isSelf = user.id === state.user.id;
			const select = h(
				'select',
				{ 'aria-label': `Role for ${user.name}`, disabled: isSelf },
				...['user', 'admin'].map((r) =>
					h('option', { value: r, selected: r === user.role }, r),
				),
			);
			select.addEventListener('change', async () => {
				try {
					await api.setRole(user.id, select.value);
				} catch (err) {
					select.value = user.role;
					box.prepend(
						banner(
							err instanceof ApiError ? err.message : 'Could not update role.',
						),
					);
				}
			});
			return h(
				'tr',
				{},
				h('td', {}, user.name),
				h('td', {}, user.email),
				h('td', {}, user.emailVerified ? 'Yes' : 'No'),
				h('td', {}, select),
			);
		});
		box.replaceChildren(
			h('h1', {}, 'Users'),
			h('p', { class: 'lede' }, `${total} registered`),
			h(
				'div',
				{ class: 'table-wrap' },
				h(
					'table',
					{},
					h(
						'thead',
						{},
						h(
							'tr',
							{},
							...['Name', 'Email', 'Verified', 'Role'].map((t) =>
								h('th', { scope: 'col' }, t),
							),
						),
					),
					h('tbody', {}, rows),
				),
			),
		);
	} catch (err) {
		box.replaceChildren(
			h('h1', {}, 'Users'),
			banner(err instanceof ApiError ? err.message : 'Could not load users.'),
		);
	}
}

// ---- router --------------------------------------------------------------

const PUBLIC = new Set([
	'/login',
	'/register',
	'/forgot-password',
	'/reset-password',
	'/verify-email',
]);

async function route() {
	const { path, params } = parseRoute();
	renderNav();

	if (!state.user && !PUBLIC.has(path)) return go('/login');
	if (state.user && (path === '/' || path === '/login' || path === '/register'))
		return go('/dashboard');

	switch (path) {
		case '/login':
			return loginView();
		case '/register':
			return registerView();
		case '/forgot-password':
			return forgotView();
		case '/reset-password':
			return resetView(params);
		case '/verify-email':
			return verifyView(params);
		case '/dashboard':
			return dashboardView();
		case '/admin':
			return state.user.role === 'admin' ? adminView() : go('/dashboard');
		default:
			return go(state.user ? '/dashboard' : '/login');
	}
}

async function start() {
	try {
		state.user = (await api.me()).user;
	} catch {
		state.user = null;
	}
	window.addEventListener('hashchange', route);
	route();
}
start();
