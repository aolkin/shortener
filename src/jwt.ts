function base64UrlDecode(str: string): Uint8Array {
	const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
	const pad = base64.length % 4;
	const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
	const binary = atob(padded);
	return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

interface JWK {
	kty: string;
	kid: string;
	use: string;
	alg: string;
	n: string;
	e: string;
}

interface JWKSResponse {
	keys: JWK[];
}

async function fetchPublicKey(jwksUrl: string, kid: string): Promise<CryptoKey> {
	const response = await fetch(jwksUrl);
	if (!response.ok) {
		throw new Error(`Failed to fetch JWKS: ${response.status}`);
	}
	const jwks: JWKSResponse = await response.json();
	const key = jwks.keys.find((k) => k.kid === kid && k.kty === 'RSA');
	if (!key) {
		throw new Error(`No matching key found for kid: ${kid}`);
	}
	return crypto.subtle.importKey(
		'jwk',
		{ kty: key.kty, n: key.n, e: key.e, alg: 'RS256' },
		{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
		false,
		['verify'],
	);
}

interface JWTHeader {
	alg: string;
	kid: string;
}

interface JWTPayload {
	aud: string | string[];
	iss: string;
	sub: string;
	email?: string;
	iat: number;
	exp: number;
	[key: string]: unknown;
}

export async function validateAccessJWT(token: string, jwksUrl: string, expectedAud: string): Promise<JWTPayload> {
	const parts = token.split('.');
	if (parts.length !== 3) {
		throw new Error('Invalid JWT format');
	}
	const [headerB64, payloadB64, signatureB64] = parts;

	const header: JWTHeader = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64)));
	if (header.alg !== 'RS256') {
		throw new Error(`Unsupported algorithm: ${header.alg}`);
	}

	const payload: JWTPayload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));

	const now = Math.floor(Date.now() / 1000);
	if (payload.exp < now) {
		throw new Error('Token expired');
	}

	const audArray = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
	if (!audArray.includes(expectedAud)) {
		throw new Error('Invalid audience');
	}

	const key = await fetchPublicKey(jwksUrl, header.kid);
	const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
	const signature = base64UrlDecode(signatureB64);

	const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, signingInput);
	if (!valid) {
		throw new Error('Invalid signature');
	}

	return payload;
}
