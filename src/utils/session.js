// Promise wrappers around express-session callbacks.
export const regenerateSession = (req) =>
	new Promise((resolve, reject) =>
		req.session.regenerate((err) => (err ? reject(err) : resolve())),
	);

export const destroySession = (req) =>
	new Promise((resolve, reject) =>
		req.session.destroy((err) => (err ? reject(err) : resolve())),
	);
