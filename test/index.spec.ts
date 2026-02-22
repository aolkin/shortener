import { env, createExecutionContext, waitOnExecutionContext, fetchMock } from 'cloudflare:test';
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import worker from '../src/index';

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

const TEST_KID = 'test-key-1';
const TEST_AUD = 'test-audience-tag';
const TEST_JWKS_URL = 'https://test-team.cloudflareaccess.com/cdn-cgi/access/certs';

let testPrivateKey: CryptoKey;
let testPublicJWK: JsonWebKey;

async function createJWT(payload: Record<string, unknown>, privateKey: CryptoKey, kid: string): Promise<string> {
	const header = { alg: 'RS256', kid, typ: 'JWT' };
	const encodeSegment = (obj: unknown) => {
		const json = JSON.stringify(obj);
		const bytes = new TextEncoder().encode(json);
		return btoa(String.fromCharCode(...bytes))
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=+$/, '');
	};
	const headerB64 = encodeSegment(header);
	const payloadB64 = encodeSegment(payload);
	const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
	const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, signingInput);
	const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
	return `${headerB64}.${payloadB64}.${signatureB64}`;
}

function validPayload() {
	const now = Math.floor(Date.now() / 1000);
	return {
		aud: [TEST_AUD],
		iss: 'https://test-team.cloudflareaccess.com',
		sub: 'user-id',
		email: 'user@example.com',
		iat: now - 60,
		exp: now + 3600,
	};
}

function mockJWKS() {
	fetchMock
		.get('https://test-team.cloudflareaccess.com')
		.intercept({ path: '/cdn-cgi/access/certs' })
		.reply(200, JSON.stringify({ keys: [{ ...testPublicJWK, kid: TEST_KID, use: 'sig', alg: 'RS256' }] }));
}

beforeAll(async () => {
	const keyPair = await crypto.subtle.generateKey(
		{ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
		true,
		['sign', 'verify'],
	);
	testPrivateKey = keyPair.privateKey;
	testPublicJWK = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

	fetchMock.activate();
	fetchMock.disableNetConnect();
});

afterEach(() => {
	fetchMock.assertNoPendingInterceptors();
	fetchMock.deactivate();
	fetchMock.activate();
	fetchMock.disableNetConnect();
});

describe('bare domain (no path)', () => {
	it('returns Niente page when no secrets are configured', async () => {
		const request = new IncomingRequest('http://example.com/');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(200);
		expect(response.headers.get('Content-Type')).toBe('text/html;charset=UTF-8');
		const body = await response.text();
		expect(body).toContain('Niente');
		expect(body).not.toContain('<form');
	});

	it('returns Niente page on POST when no secrets are configured', async () => {
		const body = new URLSearchParams({ slug: 'x', url: 'https://example.org' });
		const request = new IncomingRequest('http://example.com/', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: body.toString(),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(200);
		const html = await response.text();
		expect(html).toContain('Niente');
		expect(html).not.toContain('<form');
	});

	it('returns form page when JWT is valid', async () => {
		const token = await createJWT(validPayload(), testPrivateKey, TEST_KID);
		mockJWKS();

		const request = new IncomingRequest('http://example.com/', {
			headers: { 'Cf-Access-Jwt-Assertion': token },
		});
		const ctx = createExecutionContext();
		const testEnv = { ...env, CF_ACCESS_AUD: TEST_AUD, CF_ACCESS_JWKS_URL: TEST_JWKS_URL };
		const response = await worker.fetch(request, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(200);
		const body = await response.text();
		expect(body).toContain('<form method="POST">');
		expect(body).toContain('Create Short URL');
	});

	it('creates short URL on POST with valid JWT', async () => {
		const token = await createJWT(validPayload(), testPrivateKey, TEST_KID);
		mockJWKS();

		const body = new URLSearchParams({ slug: 'test-slug', url: 'https://example.org' });
		const request = new IncomingRequest('http://example.com/', {
			method: 'POST',
			headers: {
				'Cf-Access-Jwt-Assertion': token,
				'Content-Type': 'application/x-www-form-urlencoded',
			},
			body: body.toString(),
		});
		const ctx = createExecutionContext();
		const testEnv = { ...env, CF_ACCESS_AUD: TEST_AUD, CF_ACCESS_JWKS_URL: TEST_JWKS_URL };
		const response = await worker.fetch(request, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(200);
		const html = await response.text();
		expect(html).toContain('Created');
		expect(html).toContain('test-slug');

		const stored = await env.SHORT_URLS.get('test-slug');
		expect(stored).toBe('https://example.org');
	});

	it('returns 403 on POST without JWT when secrets configured', async () => {
		const body = new URLSearchParams({ slug: 'x', url: 'https://example.org' });
		const request = new IncomingRequest('http://example.com/', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: body.toString(),
		});
		const ctx = createExecutionContext();
		const testEnv = { ...env, CF_ACCESS_AUD: TEST_AUD, CF_ACCESS_JWKS_URL: TEST_JWKS_URL };
		const response = await worker.fetch(request, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(403);
	});

	it('returns 400 on POST with missing form fields', async () => {
		const token = await createJWT(validPayload(), testPrivateKey, TEST_KID);
		mockJWKS();

		const body = new URLSearchParams({ slug: 'test-slug' });
		const request = new IncomingRequest('http://example.com/', {
			method: 'POST',
			headers: {
				'Cf-Access-Jwt-Assertion': token,
				'Content-Type': 'application/x-www-form-urlencoded',
			},
			body: body.toString(),
		});
		const ctx = createExecutionContext();
		const testEnv = { ...env, CF_ACCESS_AUD: TEST_AUD, CF_ACCESS_JWKS_URL: TEST_JWKS_URL };
		const response = await worker.fetch(request, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(400);
		const html = await response.text();
		expect(html).toContain('Error');
	});

	it('returns 403 when no JWT header is present and secrets are configured', async () => {
		const request = new IncomingRequest('http://example.com/');
		const ctx = createExecutionContext();
		const testEnv = { ...env, CF_ACCESS_AUD: TEST_AUD, CF_ACCESS_JWKS_URL: TEST_JWKS_URL };
		const response = await worker.fetch(request, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(403);
	});

	it('returns 403 when JWT has expired', async () => {
		const payload = validPayload();
		payload.exp = Math.floor(Date.now() / 1000) - 3600;
		const token = await createJWT(payload, testPrivateKey, TEST_KID);

		const request = new IncomingRequest('http://example.com/', {
			headers: { 'Cf-Access-Jwt-Assertion': token },
		});
		const ctx = createExecutionContext();
		const testEnv = { ...env, CF_ACCESS_AUD: TEST_AUD, CF_ACCESS_JWKS_URL: TEST_JWKS_URL };
		const response = await worker.fetch(request, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(403);
	});

	it('returns 403 when JWT has wrong audience', async () => {
		const payload = validPayload();
		payload.aud = ['wrong-audience'];
		const token = await createJWT(payload, testPrivateKey, TEST_KID);

		const request = new IncomingRequest('http://example.com/', {
			headers: { 'Cf-Access-Jwt-Assertion': token },
		});
		const ctx = createExecutionContext();
		const testEnv = { ...env, CF_ACCESS_AUD: TEST_AUD, CF_ACCESS_JWKS_URL: TEST_JWKS_URL };
		const response = await worker.fetch(request, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(403);
	});
});

describe('short URL redirect', () => {
	it('returns 404 for unknown short URL', async () => {
		const request = new IncomingRequest('http://example.com/nonexistent');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(404);
	});
});
