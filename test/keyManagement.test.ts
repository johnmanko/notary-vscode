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
import { suite, test } from 'mocha';
import { RefreshPeriod, KeySource, isJWKSJsonKey, getRefreshPeriodMs, calculateNextRefresh, needsRefresh } from '../src/types/keyManagement';
import { encodeToBase64, decodeFromBase64 } from '../src/utils/keyStorage';
import { KeyStorageManager } from '../src/utils/keyStorage';
import { isValidOIDCUrl } from '../src/utils/oidcKeyFetcher';
import { validateJWTStructure } from '../src/utils/jwtValidator';

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
			let storedValue: unknown;
			const context = {
				globalState: {
					get: (_key: string, defaultValue: unknown) => (storedValue ?? defaultValue),
					update: async (_key: string, value: unknown) => {
						storedValue = value;
					}
				}
			} as never;

			const storage = new KeyStorageManager(context);
			await storage.addManualKey(
				'Manual Key',
				'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest\n-----END PUBLIC KEY-----',
				'RS256',
				'RSA',
				{ kid: 'key1' }
			);

			const keys = await storage.getKeys();
			assert.strictEqual(keys.length, 1);

			const decodedModel = JSON.parse(decodeFromBase64(keys[0].keyData)) as { keys?: unknown[] };
			assert.ok(Array.isArray(decodedModel.keys));
			assert.strictEqual(decodedModel.keys?.length, 1);
			assert.strictEqual(Object.prototype.hasOwnProperty.call(decodedModel, 'preferredKeyRef'), false);
		});

		test('Should persist description and cap it at 50 characters', async () => {
			let storedValue: unknown;
			const context = {
				globalState: {
					get: (_key: string, defaultValue: unknown) => (storedValue ?? defaultValue),
					update: async (_key: string, value: unknown) => {
						storedValue = value;
					}
				}
			} as never;

			const storage = new KeyStorageManager(context);
			const longDescription = 'x'.repeat(60);
			await storage.addManualKey(
				'Described Manual Key',
				'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest\n-----END PUBLIC KEY-----',
				'RS256',
				'RSA',
				{ kid: 'key1' },
				undefined,
				longDescription
			);

			const keys = await storage.getKeys();
			assert.strictEqual(keys.length, 1);
			assert.strictEqual((keys[0].description || '').length, 50);
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
});

suite('JWT Validation', () => {
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
	});
});
