import { env } from 'node:process';
import { randomUUID } from 'node:crypto';

/**
 * List of supported OAuth providers.
 */
const supportedProviders = new Set(['github', 'gitlab']);

/**
 * Default headers for responses.
 */
const defaultHeaders = {
	'Content-Type': 'text/html;charset=UTF-8',
	// Delete CSRF token
	'Set-Cookie':
		'csrf-token=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=Lax; Secure',
};

/**
 * Escape the given string for safe use in a regular expression.
 * @param {string} string_ - Original string.
 * @returns {string} Escaped string.
 * @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions#escaping
 */
const escapeRegExp = (string_) => string_.replaceAll(/[$()*+.?[\\\]^{|}]/g, String.raw`\$&`);

/**
 * Convert the `ALLOWED_DOMAINS` environment variable into anchored regular expression sources.
 * Used both for the `site_id` check and in the callback page's opener-origin check, so a
 * hostname is matched by the same rules on either side.
 * Ported from sveltia/sveltia-cms-auth (raikeeoy fork, 2026-10-26).
 * @param {string} [allowedDomains] - Comma-separated hostnames, may contain a wildcard (`*`).
 * @returns {string[]} Regular expression sources. Empty if the variable is not configured.
 */
const getDomainPatterns = (allowedDomains) =>
	(allowedDomains ?? '')
		.split(/,/)
		.map((string_) => string_.trim())
		.filter(Boolean)
		.map((string_) => `^${escapeRegExp(string_).replaceAll(String.raw`\*`, '.+')}$`);

/**
 * Serialize a value for safe embedding in an inline `<script>` block.
 * @param {string | boolean | string[]} value - Value to serialize.
 * @returns {string} JavaScript literal.
 */
const serialize = (value) => JSON.stringify(value ?? null).replaceAll('<', '<');

/**
 * Build the popup page that hands the OAuth result to the window that opened it.
 * The token is only posted to an opener whose browser-set origin matches ALLOWED_DOMAINS:
 * `site_id` is supplied by the caller and proves nothing about who opened the popup.
 * @param {object} args - Options.
 * @param {string} [args.provider] - Backend name, e.g. `github`.
 * @param {string} [args.token] - OAuth token.
 * @param {string} [args.error] - Error message when no token is available.
 * @param {string} [args.errorCode] - Error code Sveltia/Decap use to localize the message.
 * @returns {string} HTML document.
 */
const htmlResponse = ({ provider = 'unknown', token, error, errorCode }) => {
	const state = error ? 'error' : 'success';
	const content = error ? { provider, error, errorCode } : { provider, token };

	return `
		<!doctype html><html><body><script>
			(() => {
				const trustedPatterns = ${serialize(getDomainPatterns(env.ALLOWED_DOMAINS))};
				const hasToken = ${serialize(Boolean(token))};

				const isTrusted = (origin) => {
					try {
						const { hostname } = new URL(origin);

						return trustedPatterns.some((pattern) => new RegExp(pattern).test(hostname));
					} catch {
						return false;
					}
				};

				window.addEventListener('message', ({ data, origin }) => {
					if (data !== 'authorizing:${provider}') {
						return;
					}

					// The message origin is set by the browser and cannot be forged by the sender,
					// unlike site_id. An error carries no secret, so it is always passed through.
					if (hasToken && trustedPatterns.length > 0 && !isTrusted(origin)) {
						return;
					}

					window.opener?.postMessage(
						'authorization:${provider}:${state}:${JSON.stringify(content)}',
						origin
					);
				});
				window.opener?.postMessage('authorizing:${provider}', '*');
			})();
		</script></body></html>
	`;
};

const authMiddleware = (request, response) => {
	const { origin, searchParams } = new URL(`${request.protocol}://${request.hostname}${request.originalUrl}`);

	const { provider, site_id: domain } = Object.fromEntries(searchParams);

	if (!provider || !supportedProviders.has(provider)) {
		response.set(defaultHeaders);
		response.send(htmlResponse({
			error: 'Your Git backend is not supported by the authenticator.',
			errorCode: 'UNSUPPORTED_BACKEND',
		}));
		return;
	}

	const {
		ALLOWED_DOMAINS,
		OAUTH_CLIENT_ID,
		OAUTH_CLIENT_SECRET,
		GIT_HOSTNAME = provider === 'github' ? 'github.com' : 'gitlab.com',
	} = env;

	// Check if the domain is whitelisted (same patterns as the callback page's origin check)
	const domainPatterns = getDomainPatterns(ALLOWED_DOMAINS);

	if (
		domainPatterns.length > 0
		&& domainPatterns.every((pattern) => !new RegExp(pattern).test(domain ?? ''))
	) {
		response.set(defaultHeaders);
		response.send(htmlResponse({
			provider,
			error: 'Your domain is not allowed to use the authenticator.',
			errorCode: 'UNSUPPORTED_DOMAIN',
		}));
		return;
	}

	if (!OAUTH_CLIENT_ID || !OAUTH_CLIENT_SECRET) {
		response.set(defaultHeaders);
		response.send(htmlResponse({
			provider,
			error: 'OAuth app client ID or secret is not configured.',
			errorCode: 'MISCONFIGURED_CLIENT',
		}));
		return;
	}

	// Generate a random string for CSRF protection
	const csrfToken = randomUUID().replaceAll('-', '');
	let authURL = '';

	if (provider === 'github') {
		// GitHub
		const parameters = new URLSearchParams({
			client_id: OAUTH_CLIENT_ID,
			scope: 'repo,user',
			state: csrfToken,
		});

		authURL = `https://${GIT_HOSTNAME}/login/oauth/authorize?${parameters.toString()}`;
	} else if (provider === 'gitlab') {
		// GitLab
		const parameters = new URLSearchParams({
			client_id: OAUTH_CLIENT_ID,
			redirect_uri: `${origin}/callback`,
			response_type: 'code',
			scope: 'api',
			state: csrfToken,
		});

		authURL = `https://${GIT_HOSTNAME}/oauth/authorize?${parameters.toString()}`;
	}

	response.set({
		// Cookie expires in 10 minutes; Use `SameSite=Lax` to make sure the cookie is sent by the
		// browser after redirect
		'Set-Cookie': `csrf-token=${provider}_${csrfToken}; HttpOnly; Path=/; Max-Age=600; SameSite=Lax; Secure`,
	});

	response.redirect(authURL);
};

const callbackMiddleware = async (request, response) => {
	const { origin, searchParams } = new URL(`${request.protocol}://${request.hostname}${request.originalUrl}`);

	const { code, state } = Object.fromEntries(searchParams);

	const [, provider, csrfToken]
		= request.cookies['csrf-token']?.match(/([-a-z]+)_([\da-f]{32})/) ?? [];

	if (!provider || !supportedProviders.has(provider)) {
		response.set(defaultHeaders);
		response.send(htmlResponse({
			error: 'Your Git backend is not supported by the authenticator.',
			errorCode: 'UNSUPPORTED_BACKEND',
		}));
		return;
	}

	if (!code || !state) {
		response.set(defaultHeaders);
		response.send(htmlResponse({
			provider,
			error:
						'Failed to receive an authorization code. Please try again later.',
			errorCode: 'AUTH_CODE_REQUEST_FAILED',
		}));
		return;
	}

	if (!csrfToken || state !== csrfToken) {
		response.set(defaultHeaders);
		response.send(htmlResponse({
			provider,
			error: 'Potential CSRF attack detected. Authentication flow aborted.',
			errorCode: 'CSRF_DETECTED',
		}));
		return;
	}

	const {
		OAUTH_CLIENT_ID,
		OAUTH_CLIENT_SECRET,
		GIT_HOSTNAME = provider === 'github' ? 'github.com' : 'gitlab.com',
	} = env;

	if (!OAUTH_CLIENT_ID || !OAUTH_CLIENT_SECRET) {
		response.set(defaultHeaders);
		response.send(htmlResponse({
			provider,
			error: 'OAuth app client ID or secret is not configured.',
			errorCode: 'MISCONFIGURED_CLIENT',
		}));
		return;
	}

	let tokenURL = '';
	let requestBody = {};

	if (provider === 'github') {
		// GitHub
		tokenURL = `https://${GIT_HOSTNAME}/login/oauth/access_token`;
		requestBody = {
			code,
			client_id: OAUTH_CLIENT_ID,
			client_secret: OAUTH_CLIENT_SECRET,
		};
	} else if (provider === 'gitlab') {
		// GitLab
		tokenURL = `https://${GIT_HOSTNAME}/oauth/token`;
		requestBody = {
			code,
			client_id: OAUTH_CLIENT_ID,
			client_secret: OAUTH_CLIENT_SECRET,
			grant_type: 'authorization_code',
			redirect_uri: `${origin}/callback`,
		};
	}

	let tokenResponse;
	let token = '';
	let error = '';

	try {
		tokenResponse = await fetch(tokenURL, {
			method: 'POST',
			headers: {
				Accept: 'application/json',
				'Content-Type': 'application/json',
			},
			body: JSON.stringify(requestBody),
		});
	} catch {
		response.set(defaultHeaders);
		response.send(htmlResponse({
			provider,
			error: 'Failed to request an access token. Please try again later.',
			errorCode: 'TOKEN_REQUEST_FAILED',
		}));
		return;
	}

	try {
		({ access_token: token, error } = await tokenResponse.json());
	} catch {
		response.set(defaultHeaders);
		response.send(htmlResponse({
			provider,
			error:
						'Server responded with malformed data. Please try again later.',
			errorCode: 'MALFORMED_RESPONSE',
		}));
		return;
	}

	response.set(defaultHeaders);
	response.send(htmlResponse({ provider, token, error }));
};

export default {
	auth: authMiddleware,
	callback: callbackMiddleware,
};
