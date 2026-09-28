// An error that is safe to show to clients. Anything else becomes a generic 500.
export class AppError extends Error {
	constructor(status, code, message, details) {
		super(message);
		this.name = 'AppError';
		this.status = status;
		this.code = code;
		this.details = details;
	}
}

export const validationError = (errors) =>
	new AppError(
		422,
		'VALIDATION_ERROR',
		'Please correct the highlighted fields.',
		errors,
	);
