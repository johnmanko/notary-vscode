/**
 * Copyright (C) 2026 John Manko
 * 
 * You may convey verbatim copies of the Program's source code as you receive it, in any medium, provided that you
 * conspicuously and appropriately publish on each copy an appropriate copyright notice; keep intact all notices
 * stating that this License and any non-permissive additional terms apply to the code; keep intact all notices of
 * the absence of any warranty; and give all recipients a copy of this License along with the Program.
 * 
 * SPDX-License-Identifier: GPL-3.0
 */
import * as https from 'node:https';
import * as http from 'node:http';

/**
 * JSON Web Key as returned from OIDC endpoints
 */
export interface JWK {
	kty: string;
	use?: string;
	kid?: string;
	alg?: string;
	n?: string;
	e?: string;
	x?: string;
	y?: string;
	crv?: string;
	[key: string]: unknown;
}

/**
 * JWKS response structure
 */
export interface JWKS {
	keys: JWK[];
}

/**
 * Result of fetching keys from a URL
 */
export interface FetchResult {
	success: boolean;
	publicKey?: string;
	error?: string;
	jwks?: JWKS;
}

/**
 * Make an HTTP(S) GET request
 */
function httpGet(url: string): Promise<string> {
	return new Promise((resolve, reject) => {
		const parsedUrl = new URL(url);
		const client = parsedUrl.protocol === 'https:' ? https : http;

		const options = {
			hostname: parsedUrl.hostname,
			port: parsedUrl.port,
			path: parsedUrl.pathname + parsedUrl.search,
			method: 'GET',
			headers: {
				'User-Agent': 'Notary-VSCode-Extension/1.0',
				'Accept': 'application/json'
			}
		};

		const req = client.request(options, (res) => {
			let data = '';

			res.on('data', (chunk) => {
				data += chunk;
			});

			res.on('end', () => {
				if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
					resolve(data);
				} else {
					reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
				}
			});
		});

		req.on('error', (err) => {
			reject(err);
		});

		req.setTimeout(10000, () => {
			req.destroy();
			reject(new Error('Request timeout'));
		});

		req.end();
	});
}

/**
 * Select the best key from a JWKS
 * Prefers keys marked for signature verification
 */
function selectBestKey(jwks: JWKS): JWK | undefined {
	if (!jwks.keys || jwks.keys.length === 0) {
		return undefined;
	}

	// Prefer keys with use === 'sig'
	const sigKeys = jwks.keys.filter(k => k.use === 'sig');
	if (sigKeys.length > 0) {
		return sigKeys[0];
	}

	// Otherwise, return the first key
	return jwks.keys[0];
}

/**
 * Discover JWKS URL from base URL or OpenID configuration
 */
async function discoverJwksUrl(baseUrl: string): Promise<string> {
	const parsed = new URL(baseUrl);
	
	// If URL already points to jwks.json, use it directly
	if (parsed.pathname.includes('jwks.json')) {
		return baseUrl;
	}
	
	// If URL points to openid-configuration, fetch it to get jwks_uri
	if (parsed.pathname.includes('openid-configuration')) {
		const configResponse = await httpGet(baseUrl);
		const config = JSON.parse(configResponse);
		if (config.jwks_uri) {
			return config.jwks_uri;
		}
		throw new Error('No jwks_uri found in OpenID configuration');
	}
	
	// For base URLs, try .well-known/openid-configuration
	const wellKnownUrl = `${parsed.protocol}//${parsed.host}/.well-known/openid-configuration`;
	try {
		const configResponse = await httpGet(wellKnownUrl);
		const config = JSON.parse(configResponse);
		if (config.jwks_uri) {
			return config.jwks_uri;
		}
	} catch {
		// If .well-known/openid-configuration fails, try direct .well-known/jwks.json
		const directJwksUrl = `${parsed.protocol}//${parsed.host}/.well-known/jwks.json`;
		return directJwksUrl;
	}
	
	throw new Error('Could not discover JWKS endpoint');
}

/**
 * Fetch public keys from an OIDC JWKS endpoint
 * Supports:
 * - Direct JWKS URL: https://example.com/.well-known/jwks.json
 * - OpenID configuration URL: https://example.com/.well-known/openid-configuration
 * - Base URL: https://example.com (will auto-discover via .well-known)
 */
export async function fetchOIDCKeys(url: string): Promise<FetchResult> {
	try {
		// Validate URL
		try {
			new URL(url);
		} catch {
			return {
				success: false,
				error: 'Invalid URL format'
			};
		}

		// Discover the JWKS endpoint
		const jwksUrl = await discoverJwksUrl(url);

		// Fetch the JWKS
		const response = await httpGet(jwksUrl);
		const jwks: JWKS = JSON.parse(response);

		// Validate response structure
		if (!jwks.keys || !Array.isArray(jwks.keys)) {
			return {
				success: false,
				error: 'Invalid JWKS format: missing keys array'
			};
		}

		// Select the best key
		const selectedKey = selectBestKey(jwks);
		if (!selectedKey) {
			return {
				success: false,
				error: 'No suitable keys found in JWKS'
			};
		}

		// Store selected JWK JSON as-is for persistence and UI rendering
		const publicKey = JSON.stringify(selectedKey);

		return {
			success: true,
			publicKey,
			jwks
		};

	} catch (error) {
		return {
			success: false,
			error: error instanceof Error ? error.message : 'Unknown error occurred'
		};
	}
}

/**
 * Validate if a URL is suitable for OIDC key fetching
 * Accepts:
 * - Base URLs: https://example.com
 * - OpenID configuration: https://example.com/.well-known/openid-configuration
 * - Direct JWKS: https://example.com/.well-known/jwks.json
 */
export function isValidOIDCUrl(url: string): boolean {
	try {
		const parsed = new URL(url);
		// Should be HTTPS in production (allow HTTP for testing)
		if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
			return false;
		}
		// Accept any valid HTTP(S) URL - we'll attempt discovery
		return true;
	} catch {
		return false;
	}
}
