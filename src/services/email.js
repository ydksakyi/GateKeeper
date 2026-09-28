import nodemailer from 'nodemailer';
import { config } from '../config/index.js';

// In tests (transport "memory") messages are captured here instead of being sent.
export const outbox = [];

let transporter;
function getTransporter() {
	const { host, port, secure, user, pass } = config.email.smtp;
	transporter ??= nodemailer.createTransport({
		host,
		port,
		secure,
		requireTLS: !secure, // refuse to fall back to plaintext SMTP
		auth: user ? { user, pass } : undefined,
	});
	return transporter;
}

export async function sendMail(message) {
	const mail = { from: config.email.from, ...message };
	switch (config.email.transport) {
		case 'memory':
			outbox.push(mail);
			return;
		case 'console':
			console.log(
				`\n--- dev email ---\nTo: ${mail.to}\nSubject: ${mail.subject}\n\n${mail.text}\n-----------------\n`,
			);
			return;
		default:
			await getTransporter().sendMail(mail);
	}
}

// Fire-and-forget so response time does not depend on (or reveal) whether an email was sent.
export function sendInBackground(message) {
	sendMail(message).catch((err) =>
		console.error('Email delivery failed:', err.message),
	);
}

const link = (route, token) =>
	`${config.appUrl.origin}/#/${route}?token=${encodeURIComponent(token)}`;
const hours = (ms) => Math.round(ms / 3_600_000);
const minutes = (ms) => Math.round(ms / 60_000);

export const templates = {
	verifyEmail: ({ to, name, token }) => ({
		to,
		subject: 'Verify your email address',
		text:
			`Hello ${name},\n\nConfirm your email address using this link (valid for ${hours(config.tokens.verifyTtlMs)} hours, single use):\n\n` +
			`${link('verify-email', token)}\n\nIf you did not create an account, you can ignore this message.\n`,
	}),
	passwordReset: ({ to, name, token }) => ({
		to,
		subject: 'Reset your password',
		text:
			`Hello ${name},\n\nUse this link to choose a new password (valid for ${minutes(config.tokens.resetTtlMs)} minutes, single use):\n\n` +
			`${link('reset-password', token)}\n\nIf you did not request this, ignore this message; your password has not changed.\n`,
	}),
	alreadyRegistered: ({ to }) => ({
		to,
		subject: 'You already have an account',
		text:
			'Someone tried to register with this email address, but an account already exists.\n\n' +
			`You can sign in, or reset your password from ${config.appUrl.origin}/#/forgot-password.\n\nIf this was not you, no action is needed.\n`,
	}),
};
