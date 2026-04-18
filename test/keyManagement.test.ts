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

import * as assert from 'node:assert';
import * as http from 'node:http';
import { suite, test } from 'mocha';
import { RefreshPeriod, KeySource, isJWKSJsonKey, isManualKey, isURLKey, getRefreshPeriodMs, calculateNextRefresh, needsRefresh } from '../src/types/keyManagement';
import { encodeToBase64, decodeFromBase64, KeyStorageManager } from '../src/utils/keyStorage';
import { fetchOIDCKeys, isValidOIDCUrl } from '../src/utils/oidcKeyFetcher';
import { validateJWTSignature, validateJWTStructure } from '../src/utils/jwtValidator';

function createMockContext(initialKeys?: unknown[]) {
	let storedValue: unknown = initialKeys;
	const context = {
		globalState: {
			get: (_key: string, defaultValue: unknown) => (storedValue ?? defaultValue),
			update: async (_key: string, value: unknown) => {
				storedValue = value;
			}
		}
	} as never;

	return {
		context,
		getStoredValue: () => storedValue
	};
}

interface MockResponse {
	status?: number;
	body: unknown;
}

function replaceBasePlaceholder(value: unknown, baseUrl: string): unknown {
	if (typeof value === 'string') {
		return value.replaceAll('__BASE__', baseUrl);
	}
	if (Array.isArray(value)) {
		return value.map(entry => replaceBasePlaceholder(entry, baseUrl));
	}
	if (value && typeof value === 'object') {
		return Object.fromEntries(
			Object.entries(value).map(([key, entry]) => [key, replaceBasePlaceholder(entry, baseUrl)])
		);
	}
	return value;
}

async function withJsonServer(
	routes: Record<string, MockResponse>,
	run: (baseUrl: string) => Promise<void>
): Promise<void> {
	let baseUrl = '';
	const server = http.createServer((req, res) => {
		const route = routes[req.url || '/'];
		if (!route) {
			res.writeHead(404, { 'Content-Type': 'application/json' });
			res.end(JSON.stringify({ error: 'not found' }));
			return;
		}

		const body = replaceBasePlaceholder(route.body, baseUrl);
		res.writeHead(route.status || 200, { 'Content-Type': 'application/json' });
		res.end(typeof body === 'string' ? body : JSON.stringify(body));
	});

	await new Promise<void>((resolve) => {
		server.listen(0, '127.0.0.1', () => resolve());
	});

	const address = server.address();
	if (!address || typeof address === 'string') {
		server.close();
		throw new Error('Failed to start test server');
	}

	baseUrl = `http://127.0.0.1:${address.port}`;
	try {
		await run(baseUrl);
	} finally {
		await new Promise<void>((resolve, reject) => {
			server.close((error) => {
				if (error) {
					reject(error);
					return;
				}
				resolve();
			});
		});
	}
}

suite('Key Management Types', () => {
	suite('RefreshPeriod calculations', () => {
		test('Daily period should be 24 hours in milliseconds', () => {
			const ms = getRefreshPeriodMs(RefreshPeriod.Daily);
			assert.strictEqual(ms, 24 * 60 * 60 * 1000);
		});

		test('Weekly period should be 7 days in milliseconds', () => {
			const ms = getRefreshPeriodMs(RefreshPeriod.Weekly);
			assert.strictEqual(ms, 7 * 24 * 60 * 60 * 1000);
		});

		test('Monthly period should be 30 days in milliseconds', () => {
			const ms = getRefreshPeriodMs(RefreshPeriod.Monthly);
			assert.strictEqual(ms, 30 * 24 * 60 * 60 * 1000);
		});
	});

	suite('calculateNextRefresh', () => {
		test('Should calculate correct next refresh time for daily period', () => {
			const now = Date.now();
			const nextRefresh = calculateNextRefresh(RefreshPeriod.Daily, now);
			const expected = now + (24 * 60 * 60 * 1000);
			assert.strictEqual(nextRefresh, expected);
		});

		test('Should calculate correct next refresh time for weekly period', () => {
			const now = Date.now();
			const nextRefresh = calculateNextRefresh(RefreshPeriod.Weekly, now);
			const expected = now + (7 * 24 * 60 * 60 * 1000);
			assert.strictEqual(nextRefresh, expected);
		});

		test('Should use current time when fromTime not provided', () => {
			const before = Date.now();
			const nextRefresh = calculateNextRefresh(RefreshPeriod.Daily);
			const after = Date.now();
			
			// Should be approximately 24 hours from now
			const expectedMin = before + (24 * 60 * 60 * 1000);
			const expectedMax = after + (24 * 60 * 60 * 1000);
			assert.ok(nextRefresh >= expectedMin && nextRefresh <= expectedMax);
		});
	});

	suite('needsRefresh', () => {
		test('Should return true when current time >= nextRefreshAt', () => {
			const urlKey = {
				id: 'test',
				name: 'Test Key',
				source: KeySource.URL as KeySource.URL,
				keyData: 'test',
				createdAt: Date.now() - 10000,
				url: 'https://example.com',
				refreshPeriod: RefreshPeriod.Daily,
				lastFetchedAt: Date.now() - 10000,
				nextRefreshAt: Date.now() - 1000 // In the past
			};
			
			assert.strictEqual(needsRefresh(urlKey), true);
		});

		test('Should return false when current time < nextRefreshAt', () => {
			const urlKey = {
				id: 'test',
				name: 'Test Key',
				source: KeySource.URL as KeySource.URL,
				keyData: 'test',
				createdAt: Date.now(),
				url: 'https://example.com',
				refreshPeriod: RefreshPeriod.Daily,
				lastFetchedAt: Date.now(),
				nextRefreshAt: Date.now() + 1000000 // In the future
			};
			
			assert.strictEqual(needsRefresh(urlKey), false);
		});

		test('Should return true when exactly at nextRefreshAt', () => {
			const now = Date.now();
			const urlKey = {
				id: 'test',
				name: 'Test Key',
				source: KeySource.URL as KeySource.URL,
				keyData: 'test',
				createdAt: now,
				url: 'https://example.com',
				refreshPeriod: RefreshPeriod.Daily,
				lastFetchedAt: now,
				nextRefreshAt: now
			};
			
			assert.strictEqual(needsRefresh(urlKey), true);
		});
	});

	suite('Key source types', () => {
		test('Should include jwks-json as a key source', () => {
			assert.strictEqual(KeySource.JWKSJson, 'jwks-json');
		});

		test('Should identify jwks-json keys with type guard', () => {
			const jwksKey = {
				id: 'jwks-1',
				name: 'JWKS Key',
				source: KeySource.JWKSJson as KeySource.JWKSJson,
				keyData: 'test',
				rawJwksJson: '{"keys":[]}',
				createdAt: Date.now()
			};

			assert.strictEqual(isJWKSJsonKey(jwksKey), true);
		});

		test('Should identify manual and URL keys with type guards', () => {
			const manualKey = {
				id: 'manual-1',
				name: 'Manual Key',
				source: KeySource.Manual as KeySource.Manual,
				keyData: 'test',
				createdAt: Date.now()
			};
			const urlKey = {
				id: 'url-1',
				name: 'URL Key',
				source: KeySource.URL as KeySource.URL,
				keyData: 'test',
				createdAt: Date.now(),
				url: 'https://example.com',
				refreshPeriod: RefreshPeriod.Daily,
				lastFetchedAt: Date.now(),
				nextRefreshAt: Date.now() + 1000
			};

			assert.strictEqual(isManualKey(manualKey), true);
			assert.strictEqual(isURLKey(manualKey), false);
			assert.strictEqual(isURLKey(urlKey), true);
			assert.strictEqual(isJWKSJsonKey(urlKey), false);
		});
	});
});

suite('Key Storage', () => {
	suite('Base64 encoding/decoding', () => {
		test('Should encode string to base64', () => {
			const input = 'Hello, World!';
			const encoded = encodeToBase64(input);
			assert.strictEqual(typeof encoded, 'string');
			assert.ok(encoded.length > 0);
			assert.notStrictEqual(encoded, input);
		});

		test('Should decode base64 to original string', () => {
			const input = 'Hello, World!';
			const encoded = encodeToBase64(input);
			const decoded = decodeFromBase64(encoded);
			assert.strictEqual(decoded, input);
		});

		test('Should handle empty string', () => {
			const input = '';
			const encoded = encodeToBase64(input);
			const decoded = decodeFromBase64(encoded);
			assert.strictEqual(decoded, input);
		});

		test('Should handle special characters', () => {
			const input = '🔐 Secret Key: !@#$%^&*()';
			const encoded = encodeToBase64(input);
			const decoded = decodeFromBase64(encoded);
			assert.strictEqual(decoded, input);
		});

		test('Should handle multi-line PEM-like content', () => {
			const input = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END PUBLIC KEY-----`;
			const encoded = encodeToBase64(input);
			const decoded = decodeFromBase64(encoded);
			assert.strictEqual(decoded, input);
		});

		test('Should handle JSON content', () => {
			const input = JSON.stringify({
				kty: 'RSA',
				n: 'AQAB',
				e: 'AQAB'
			});
			const encoded = encodeToBase64(input);
			const decoded = decodeFromBase64(encoded);
			assert.strictEqual(decoded, input);
		});

		test('Should persist manual keys as a single-key JWKS model', async () => {
			const { context } = createMockContext();
			const storage = new KeyStorageManager(context);
			await storage.addManualKey(
				'Manual Key',
				'RS256',
				'RSA',
				{ kid: 'key1' }
			);

			const keys = await storage.getKeys();
			assert.strictEqual(keys.length, 1);

			const decodedModel = JSON.parse(decodeFromBase64(keys[0].keyData)) as { keys?: unknown[] };
			assert.ok(Array.isArray(decodedModel.keys));
			assert.strictEqual(decodedModel.keys?.length, 1);
			assert.strictEqual(Object.hasOwn(decodedModel, 'preferredKeyRef'), false);
		});

		test('Should persist description and cap it at 50 characters', async () => {
			const { context } = createMockContext();
			const storage = new KeyStorageManager(context);
			const longDescription = 'x'.repeat(60);
			await storage.addManualKey(
				'Described Manual Key',
				'RS256',
				'RSA',
				{ kid: 'key1' },
				longDescription
			);

			const keys = await storage.getKeys();
			assert.strictEqual(keys.length, 1);
			assert.strictEqual((keys[0].description || '').length, 50);
		});

		test('Should add URL and JWKS JSON keys and retrieve them by id', async () => {
			const { context } = createMockContext();
			const storage = new KeyStorageManager(context);
			const urlKey = await storage.addURLKey(
				'URL Key',
				'https://issuer.example/.well-known/jwks.json',
				RefreshPeriod.Weekly,
				[{ kty: 'RSA', kid: 'url-key' }],
				'url description'
			);
			const jwksKey = await storage.addJWKSJsonKey(
				'JWKS Key',
				'{"keys":[{"kid":"jwks-key"}]}',
				[{ kty: 'RSA', kid: 'jwks-key' }],
				'jwks description'
			);

			assert.strictEqual((await storage.getKeys()).length, 2);
			assert.strictEqual((await storage.getKeyById(urlKey.id))?.name, 'URL Key');
			assert.strictEqual((await storage.getKeyById(jwksKey.id))?.source, KeySource.JWKSJson);
			assert.strictEqual(await storage.getKeyById('missing'), undefined);
		});

		test('Should update URL keys and editable URL settings', async () => {
			const { context } = createMockContext();
			const storage = new KeyStorageManager(context);
			const urlKey = await storage.addURLKey(
				'URL Key',
				'https://issuer.example/.well-known/jwks.json',
				RefreshPeriod.Daily,
				[{ kty: 'RSA', kid: 'old-key' }]
			);

			const updated = await storage.updateURLKey(urlKey.id, [{ kty: 'RSA', kid: 'new-key' }]);
			assert.strictEqual(updated?.lastFetchedAt !== undefined, true);
			assert.strictEqual(JSON.parse(decodeFromBase64(updated?.keyData || '')).keys[0].kid, 'new-key');

			const settingsUpdated = await storage.updateURLKeySettings(
				urlKey.id,
				'Renamed URL Key',
				RefreshPeriod.Monthly,
				'updated description'
			);
			assert.strictEqual(settingsUpdated?.name, 'Renamed URL Key');
			assert.strictEqual(settingsUpdated?.refreshPeriod, RefreshPeriod.Monthly);
			assert.strictEqual(settingsUpdated?.description, 'updated description');
			assert.strictEqual(await storage.updateURLKey('missing', []), undefined);
			assert.strictEqual(await storage.updateURLKeySettings('missing', 'Unused', RefreshPeriod.Daily), undefined);
		});

		test('Should update manual and JWKS JSON keys and reject wrong update methods', async () => {
			const { context } = createMockContext();
			const storage = new KeyStorageManager(context);
			const manualKey = await storage.addManualKey('Manual Key', 'RS256', 'RSA', { kid: 'manual-1' }, 'manual description');
			const jwksKey = await storage.addJWKSJsonKey('JWKS Key', '{"keys":[]}', [{ kty: 'RSA', kid: 'jwks-1' }], 'jwks description');

			const updatedManual = await storage.updateManualKey(
				manualKey.id,
				'Updated Manual Key',
				'ES256',
				'EC',
				{ kid: 'manual-2', typ: 'at+jwt', use: 'enc' },
				'updated manual description'
			);
			const decodedManual = JSON.parse(decodeFromBase64(updatedManual?.keyData || '')) as { keys: Array<Record<string, unknown>> };
			assert.strictEqual(updatedManual?.name, 'Updated Manual Key');
			assert.strictEqual(updatedManual?.description, 'updated manual description');
			assert.strictEqual(decodedManual.keys[0].kty, 'EC');
			assert.strictEqual(decodedManual.keys[0].alg, 'ES256');
			assert.strictEqual(decodedManual.keys[0].kid, 'manual-2');
			assert.strictEqual(decodedManual.keys[0].typ, 'at+jwt');

			const updatedJwks = await storage.updateJWKSJsonKey(
				jwksKey.id,
				'Updated JWKS Key',
				'{"keys":[{"kid":"jwks-2"}]}',
				[{ kty: 'RSA', kid: 'jwks-2' }],
				'updated jwks description'
			);
			assert.strictEqual(updatedJwks?.name, 'Updated JWKS Key');
			assert.strictEqual(updatedJwks?.rawJwksJson, '{"keys":[{"kid":"jwks-2"}]}');
			assert.strictEqual(updatedJwks?.description, 'updated jwks description');

			await assert.rejects(() => storage.updateURLKeySettings(manualKey.id, 'Invalid', RefreshPeriod.Daily), /manual key/);
			await assert.rejects(() => storage.updateManualKey(jwksKey.id, 'Invalid'), /URL key as manual key/);
			await assert.rejects(() => storage.updateJWKSJsonKey(manualKey.id, 'Invalid', '{"keys":[]}', []), /non-JWKS JSON key/);
			await assert.rejects(() => storage.updateURLKey(jwksKey.id, []), /non-URL key/);
			assert.strictEqual(await storage.updateManualKey('missing', 'Missing'), undefined);
			assert.strictEqual(await storage.updateJWKSJsonKey('missing', 'Missing', '{"keys":[]}', []), undefined);
		});

		test('Should rename, decode, delete, and clear keys', async () => {
			const { context, getStoredValue } = createMockContext();
			const storage = new KeyStorageManager(context);
			const manualKey = await storage.addManualKey('Manual Key', 'RS256', 'RSA', { kid: 'manual-1' });
			const urlKey = await storage.addURLKey('URL Key', 'https://issuer.example/jwks', RefreshPeriod.Daily, [{ kty: 'RSA', kid: 'url-1' }]);

			const renamed = await storage.updateKeyName(manualKey.id, 'Renamed Key', 'renamed description');
			assert.strictEqual(renamed?.name, 'Renamed Key');
			assert.strictEqual(renamed?.description, 'renamed description');
			assert.strictEqual(await storage.updateKeyName('missing', 'Nope'), undefined);

			const decoded = storage.getDecodedKey(urlKey);
			assert.strictEqual(JSON.parse(decoded).keys[0].kid, 'url-1');

			assert.strictEqual(await storage.deleteKey(manualKey.id), true);
			assert.strictEqual(await storage.deleteKey(manualKey.id), false);
			assert.strictEqual((await storage.getKeys()).length, 1);

			await storage.clearAllKeys();
			assert.deepStrictEqual(getStoredValue(), []);
			assert.strictEqual((await storage.getKeys()).length, 0);
		});
	});
});

suite('OIDC Key Fetcher', () => {
	suite('OIDC URL validation', () => {
		test('Should accept HTTPS URLs with jwks in path', () => {
			assert.strictEqual(isValidOIDCUrl('https://example.com/.well-known/jwks.json'), true);
		});

		test('Should accept HTTPS URLs with keys in path', () => {
			assert.strictEqual(isValidOIDCUrl('https://auth.example.com/keys'), true);
		});

		test('Should accept HTTPS URLs with .well-known', () => {
			assert.strictEqual(isValidOIDCUrl('https://example.com/.well-known/openid-configuration'), true);
		});

		test('Should accept HTTP URLs (for testing)', () => {
			assert.strictEqual(isValidOIDCUrl('http://localhost:8080/jwks'), true);
		});

		test('Should accept base URLs for auto-discovery', () => {
			assert.strictEqual(isValidOIDCUrl('https://example.com'), true);
		});

		test('Should accept any valid HTTP(S) URL path', () => {
			assert.strictEqual(isValidOIDCUrl('https://example.com/auth/realms/myrealm'), true);
		});

		test('Should reject non-HTTP(S) protocols', () => {
			assert.strictEqual(isValidOIDCUrl('ftp://example.com/jwks'), false);
		});

		test('Should reject invalid URLs', () => {
			assert.strictEqual(isValidOIDCUrl('not-a-url'), false);
		});
	});

	suite('fetchOIDCKeys', () => {
		const jwksBody = {
			keys: [
				{ kty: 'RSA', use: 'enc', kid: 'enc-key', n: 'abc', e: 'AQAB' },
				{ kty: 'RSA', use: 'sig', kid: 'sig-key', n: 'def', e: 'AQAB', alg: 'RS256' }
			]
		};

		test('Should discover JWKS from base root URL via well-known openid configuration', async () => {
			await withJsonServer({
				'/.well-known/openid-configuration': { body: { jwks_uri: '__BASE__/.well-known/jwks.json' } },
				'/.well-known/jwks.json': { body: jwksBody }
			}, async (baseUrl) => {
				const result = await fetchOIDCKeys(baseUrl);
				assert.strictEqual(result.success, true);
				assert.strictEqual(result.jwks?.keys.length, 2);
				assert.strictEqual(JSON.parse(result.publicKey || '{}').kid, 'sig-key');
			});
		});

		test('Should resolve JWKS from explicit openid-configuration URL', async () => {
			await withJsonServer({
				'/.well-known/openid-configuration': { body: { jwks_uri: '__BASE__/jwks-key' } },
				'/jwks-key': { body: jwksBody }
			}, async (baseUrl) => {
				const result = await fetchOIDCKeys(`${baseUrl}/.well-known/openid-configuration`);
				assert.strictEqual(result.success, true);
				assert.strictEqual(JSON.parse(result.publicKey || '{}').kid, 'sig-key');
			});
		});

		test('Should accept direct standard jwks.json endpoint', async () => {
			await withJsonServer({
				'/.well-known/jwks.json': { body: jwksBody }
			}, async (baseUrl) => {
				const result = await fetchOIDCKeys(`${baseUrl}/.well-known/jwks.json`);
				assert.strictEqual(result.success, true);
				assert.strictEqual(result.jwks?.keys.length, 2);
			});
		});

		test('Should accept direct non-standard JWKS endpoint names', async () => {
			await withJsonServer({
				'/jwks-key': { body: jwksBody }
			}, async (baseUrl) => {
				const result = await fetchOIDCKeys(`${baseUrl}/jwks-key`);
				assert.strictEqual(result.success, true);
				assert.strictEqual(JSON.parse(result.publicKey || '{}').kid, 'sig-key');
			});
		});

		test('Should treat non-root context URL as OIDC config when it returns jwks_uri', async () => {
			await withJsonServer({
				'/auth/realm': { body: { jwks_uri: '__BASE__/auth/realm/jwks-key' } },
				'/auth/realm/jwks-key': { body: jwksBody }
			}, async (baseUrl) => {
				const result = await fetchOIDCKeys(`${baseUrl}/auth/realm`);
				assert.strictEqual(result.success, true);
				assert.strictEqual(JSON.parse(result.publicKey || '{}').kid, 'sig-key');
			});
		});

		test('Should fail for non-root URLs that are neither JWKS nor OIDC config', async () => {
			await withJsonServer({
				'/custom/path': { body: { issuer: '__BASE__/issuer', message: 'not jwks' } },
				'/.well-known/openid-configuration': { status: 404, body: { error: 'missing' } }
			}, async (baseUrl) => {
				const result = await fetchOIDCKeys(`${baseUrl}/custom/path`);
				assert.strictEqual(result.success, false);
				assert.ok((result.error || '').includes('HTTP 404') || (result.error || '').includes('Invalid JWKS format'));
			});
		});

			test('Should fall back to default well-known jwks endpoint when discovery config is unavailable', async () => {
				await withJsonServer({
					'/.well-known/openid-configuration': { status: 404, body: { error: 'missing' } },
					'/.well-known/jwks.json': { body: jwksBody }
				}, async (baseUrl) => {
					const result = await fetchOIDCKeys(baseUrl);
					assert.strictEqual(result.success, true);
					assert.strictEqual(result.jwks?.keys.length, 2);
				});
			});

			test('Should reject invalid url text before making a request', async () => {
				const result = await fetchOIDCKeys('not-a-url');
				assert.strictEqual(result.success, false);
				assert.strictEqual(result.error, 'Invalid URL format');
			});

			test('Should reject JWKS responses without a keys array', async () => {
				await withJsonServer({
					'/.well-known/openid-configuration': { body: { jwks_uri: '__BASE__/broken-jwks' } },
					'/broken-jwks': { body: { items: [] } }
				}, async (baseUrl) => {
					const result = await fetchOIDCKeys(`${baseUrl}/.well-known/openid-configuration`);
					assert.strictEqual(result.success, false);
					assert.strictEqual(result.error, 'Invalid JWKS format: missing keys array');
				});
			});

			test('Should reject JWKS responses with an empty keys array', async () => {
				await withJsonServer({
					'/empty-jwks': { body: { keys: [] } }
				}, async (baseUrl) => {
					const result = await fetchOIDCKeys(`${baseUrl}/empty-jwks`);
					assert.strictEqual(result.success, false);
					assert.strictEqual(result.error, 'No suitable keys found in JWKS');
				});
			});

			test('Should report missing jwks_uri in explicit openid configuration responses', async () => {
				await withJsonServer({
					'/.well-known/openid-configuration': { body: { issuer: '__BASE__' } }
				}, async (baseUrl) => {
					const result = await fetchOIDCKeys(`${baseUrl}/.well-known/openid-configuration`);
					assert.strictEqual(result.success, false);
					assert.strictEqual(result.error, 'No jwks_uri found in OpenID configuration');
				});
			});

			test('Should recover from malformed non-root responses by falling back to root discovery', async () => {
				await withJsonServer({
					'/auth/realm': { body: '{bad json' },
					'/.well-known/openid-configuration': { body: { jwks_uri: '__BASE__/.well-known/jwks.json' } },
					'/.well-known/jwks.json': { body: jwksBody }
				}, async (baseUrl) => {
					const result = await fetchOIDCKeys(`${baseUrl}/auth/realm`);
					assert.strictEqual(result.success, true);
					assert.strictEqual(JSON.parse(result.publicKey || '{}').kid, 'sig-key');
				});
			});

			test('Should fail root discovery when openid configuration has no jwks_uri', async () => {
				await withJsonServer({
					'/.well-known/openid-configuration': { body: { issuer: '__BASE__' } }
				}, async (baseUrl) => {
					const result = await fetchOIDCKeys(baseUrl);
					assert.strictEqual(result.success, false);
					assert.strictEqual(result.error, 'Could not discover JWKS endpoint');
				});
			});

			test('Should fall back to the first key when no sig-designated key exists', async () => {
				await withJsonServer({
					'/enc-only-jwks': {
						body: {
							keys: [
								{ kty: 'RSA', use: 'enc', kid: 'first-key', n: 'abc', e: 'AQAB' },
								{ kty: 'RSA', use: 'enc', kid: 'second-key', n: 'def', e: 'AQAB' }
							]
						}
					}
				}, async (baseUrl) => {
					const result = await fetchOIDCKeys(`${baseUrl}/enc-only-jwks`);
					assert.strictEqual(result.success, true);
					assert.strictEqual(JSON.parse(result.publicKey || '{}').kid, 'first-key');
				});
			});
	});
});

suite('JWT Validation', () => {
	suite('JWT signature validation', () => {
		test('Should verify a valid RS256 token against a PEM public key', async () => {
			const jose = await import('jose');
			const { publicKey, privateKey } = await jose.generateKeyPair('RS256');
			const publicKeyPem = await jose.exportSPKI(publicKey);
			const token = await new jose.SignJWT({ sub: '1234567890' })
				.setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'pem-key' })
				.sign(privateKey);

			const result = await validateJWTSignature(token, publicKeyPem, {
				algorithm: 'RS256',
				typ: 'JWT',
				kid: 'pem-key'
			});

			assert.strictEqual(result.valid, true);
			assert.strictEqual(result.details?.keyType, 'PEM');
		});

		test('Should verify a valid RS256 token against a JWK public key', async () => {
			const jose = await import('jose');
			const { publicKey, privateKey } = await jose.generateKeyPair('RS256');
			const publicJwk = await jose.exportJWK(publicKey);
			const token = await new jose.SignJWT({ scope: 'read:all' })
				.setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'jwk-key' })
				.sign(privateKey);

			const result = await validateJWTSignature(token, JSON.stringify({ ...publicJwk, kid: 'jwk-key' }), {
				algorithm: 'RS256',
				typ: 'JWT',
				kid: 'jwk-key'
			});

			assert.strictEqual(result.valid, true);
			assert.strictEqual(result.details?.keyType, 'JWK');
		});

		test('Should fail when metadata algorithm does not match the token', async () => {
			const jose = await import('jose');
			const { publicKey, privateKey } = await jose.generateKeyPair('RS256');
			const publicKeyPem = await jose.exportSPKI(publicKey);
			const token = await new jose.SignJWT({ sub: '1234567890' })
				.setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'pem-key' })
				.sign(privateKey);

			const result = await validateJWTSignature(token, publicKeyPem, {
				algorithm: 'ES256',
				typ: 'JWT'
			});

			assert.strictEqual(result.valid, false);
			assert.ok(result.message.includes('algorithm mismatch'));
		});

		test('Should fail when metadata typ or kid does not match the token header', async () => {
			const jose = await import('jose');
			const { publicKey, privateKey } = await jose.generateKeyPair('RS256');
			const publicKeyPem = await jose.exportSPKI(publicKey);
			const token = await new jose.SignJWT({ sub: '1234567890' })
				.setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'actual-kid' })
				.sign(privateKey);

			const typResult = await validateJWTSignature(token, publicKeyPem, {
				algorithm: 'RS256',
				typ: 'AT+JWT'
			});
			assert.strictEqual(typResult.valid, false);
			assert.ok(typResult.message.includes('type mismatch'));

			const kidResult = await validateJWTSignature(token, publicKeyPem, {
				algorithm: 'RS256',
				typ: 'JWT',
				kid: 'expected-kid'
			});
			assert.strictEqual(kidResult.valid, false);
			assert.ok(kidResult.message.includes('key id mismatch'));
		});

		test('Should format non-string typ and kid header values in metadata mismatch errors', async () => {
			const jose = await import('jose');
			const { publicKey, privateKey } = await jose.generateKeyPair('RS256');
			const publicKeyPem = await jose.exportSPKI(publicKey);
			const tokenWithNumericTyp = await new jose.SignJWT({ sub: '1234567890' })
				.setProtectedHeader({ alg: 'RS256', typ: 123 as unknown as 'JWT' })
				.sign(privateKey);
			const typResult = await validateJWTSignature(tokenWithNumericTyp, publicKeyPem, {
				algorithm: 'RS256',
				typ: 'JWT'
			});
			assert.strictEqual(typResult.valid, false);
			assert.ok(typResult.message.includes('[non-string value]'));

			const tokenWithNumericKid = await new jose.SignJWT({ sub: '1234567890' })
				.setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 123 as unknown as string })
				.sign(privateKey);
			const kidResult = await validateJWTSignature(tokenWithNumericKid, publicKeyPem, {
				algorithm: 'RS256',
				typ: 'JWT',
				kid: 'expected-kid'
			});
			assert.strictEqual(kidResult.valid, false);
			assert.ok(kidResult.message.includes('[non-string value]'));
		});

		test('Should reject invalid token format before signature verification', async () => {
			const result = await validateJWTSignature('not-a-jwt', '-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----');
			assert.strictEqual(result.valid, false);
			assert.ok(result.message.includes('Invalid JWT format'));
		});

		test('Should reject tokens that are missing alg in the header', async () => {
			const token = 'eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature';
			const result = await validateJWTSignature(token, '-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----');
			assert.strictEqual(result.valid, false);
			assert.ok(result.message.includes('missing "alg"'));
		});

		test('Should reject unknown public key formats', async () => {
			const jose = await import('jose');
			const { privateKey } = await jose.generateKeyPair('RS256');
			const token = await new jose.SignJWT({ sub: '1234567890' })
				.setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
				.sign(privateKey);

			const result = await validateJWTSignature(token, 'not a public key');
			assert.strictEqual(result.valid, false);
			assert.ok(result.message.includes('Unknown key format'));
			assert.strictEqual(result.details?.keyType, 'unknown');
		});

		test('Should surface cryptographic verification failures', async () => {
			const jose = await import('jose');
			const signingKeys = await jose.generateKeyPair('RS256');
			const wrongKeys = await jose.generateKeyPair('RS256');
			const wrongPublicPem = await jose.exportSPKI(wrongKeys.publicKey);
			const token = await new jose.SignJWT({ sub: '1234567890' })
				.setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
				.sign(signingKeys.privateKey);

			const result = await validateJWTSignature(token, wrongPublicPem);
			assert.strictEqual(result.valid, false);
			assert.ok(result.message.includes('verification failed'));
			assert.ok((result.details?.error || '').length > 0);
		});
	});

	suite('JWT structure validation', () => {
		test('Should validate a well-formed JWT structure', () => {
			const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
			const result = validateJWTStructure(token);
			assert.strictEqual(result.valid, true);
		});

		test('Should reject invalid JWT format', () => {
			const token = 'invalid.jwt';
			const result = validateJWTStructure(token);
			assert.strictEqual(result.valid, false);
			assert.ok(result.message.includes('Invalid JWT'));
		});

		test('Should reject JWT without algorithm', () => {
			// Header without alg: {"typ":"JWT"}
			const token = 'eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature';
			const result = validateJWTStructure(token);
			assert.strictEqual(result.valid, false);
			assert.ok(result.message.includes('alg'));
		});

		test('Should note when typ is not JWT', () => {
			// Header with typ: "AT+JWT" (access token)
			const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkFUK0pXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature';
			const result = validateJWTStructure(token);
			assert.strictEqual(result.valid, false);
			assert.ok(result.message.toLowerCase().includes('typ'));
		});

		test('Should reject JWT structure when typ is missing', () => {
			const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature';
			const result = validateJWTStructure(token);
			assert.strictEqual(result.valid, false);
			assert.ok(result.message.toLowerCase().includes('typ'));
		});
	});
});
