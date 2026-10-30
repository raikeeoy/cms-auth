// This file owns the tests for the callback page's opener-origin check: the OAuth token may only
// be handed to a window whose browser-set origin matches ALLOWED_DOMAINS, never to a page that
// merely claims an allowed site_id.
import vm from 'node:vm';
import { randomUUID } from 'node:crypto';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import express from 'express';
import request from 'supertest';
import {
	afterEach,
	expect,
	test,
	vi,
} from 'vitest';
import middleware from '../middleware/index.js';

dotenv.config({ path: '.env.test', silent: true });

const TOKEN = 'gho_test_token_value';

/**
 * Render the callback page for a successful (or failed) token exchange.
 * @param {object} [tokenJson] - Body the mocked GitHub token endpoint returns; defaults to a token.
 * @returns {Promise<string>} The HTML the callback route sends.
 */
const renderCallback = async (tokenJson) => {
	const body = tokenJson ?? { access_token: TOKEN };
	vi.stubGlobal('fetch', vi.fn(async () => ({ json: async () => body })));
	const app = express();
	app.use(cookieParser());
	app.get('/callback', middleware.callback);
	const state = randomUUID().replaceAll('-', '');
	const response = await request(app)
		.get(`/callback?code=123456789&state=${state}`)
		.set('Cookie', [`csrf-token=github_${state}`])
		.send();
	return response.text;
};

/**
 * Run the page's inline script in a fake popup window and deliver one message to it.
 * @param {string} html - Callback page HTML.
 * @param {string} origin - Browser-set origin of the window sending `authorizing:github`.
 * @returns {Array<[string, string]>} Every postMessage call the popup made to its opener.
 */
const handshake = (html, origin) => {
	const script = html.match(/<script>([\s\S]*)<\/script>/)[1];
	const calls = [];
	let onMessage;
	const window = {
		opener: {
			postMessage(message, target) {
				calls.push([message, target]);
			},
		},
		addEventListener(type, handler) {
			if (type === 'message') {
				onMessage = handler;
			}
		},
	};
	vm.runInNewContext(script, { window, URL });
	onMessage({ data: 'authorizing:github', origin });
	return calls;
};

const sentToken = (calls) => calls.some(([message]) => message.includes(TOKEN));

afterEach(() => {
	vi.unstubAllGlobals();
});

test('token is handed to an allowed origin', async () => {
	const calls = handshake(await renderCallback(), 'https://cms.example.com');
	expect(sentToken(calls)).toBe(true);
	expect(calls.at(-1)[1]).toBe('https://cms.example.com');
});

test('token is NOT handed to an origin outside ALLOWED_DOMAINS', async () => {
	const calls = handshake(await renderCallback(), 'https://evil.test');
	expect(sentToken(calls)).toBe(false);
});

test('token is NOT handed to a look-alike origin (pattern must be anchored)', async () => {
	const calls = handshake(await renderCallback(), 'https://example.com.evil.test');
	expect(sentToken(calls)).toBe(false);
});

test('an error (no secret) still reaches any origin so the sign-in screen can explain it', async () => {
	const calls = handshake(await renderCallback({ error: 'bad_verification_code' }), 'https://evil.test');
	expect(calls.some(([message]) => message.startsWith('authorization:github:error:'))).toBe(true);
});
