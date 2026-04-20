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
import * as crypto from 'node:crypto';
import * as http from 'node:http';
import { suite, test } from 'mocha';
import { KeyManager } from '../src/utils/keyManager';
import { encodeToBase64 } from '../src/utils/keyStorage';
import { JWKSJsonValidationKey, KeySource, RefreshPeriod, URLValidationKey, ValidationKey } from '../src/types/keyManagement';
import { validateJWTSignature } from '../src/utils/jwtValidator';

const VALID_RSA_N = 't5OyWWeUS4WVIPQGky-EfXuT3RlvWRACfjc5pt-Xfi2XhF-YOF_eL3Igz7Ck56fXCxTszSyk2-X_DQZDgT0i2LbvN_WXmixMnn9swMh_Q3TPF3cKxzK8AlOryFKAhaoXvmnjBGjKi40Nw3uRUSth0RD5vyEnAWblNkbJp1GEMJiZgD3o5xXe3z3k3YI9-msWI0Xyd_lUOpJ85MnZJuNyMS-437ZS7KlDMmb5xFIOLD3iU_ScHhKcKIZFfQxqBlwuG-2qShgylHH1XZiFxjKfGMRyFPr4y2RhmyPW-B1oIsrPbmIBocELKY8HDMFmsST2zRQuji9TPc8kqpbLXG4Sew';

const VALID_KEY_1: Record<string, unknown> = {
	kty: 'RSA',
	n: VALID_RSA_N,
	e: 'AQAB',
	use: 'sig',
	alg: 'RS256',
	kid: 'key1'
};

const VALID_KEY_2: Record<string, unknown> = {
	...VALID_KEY_1,
	kid: 'key2'
};

const INVALID_KEY_3: Record<string, unknown> = {
	kty: 'RSA',
	n: 't5OyWWeUS4WVIPQGky-EfXuT3RlvWRACfjc5pt',
	e: 'AQAB',
	use: 'sig',
	alg: 'RS256',
	kid: 'key3'
};

function createManager(): KeyManager {
	return new KeyManager({} as never);
}

function createManagerWithContext(initialKeys?: ValidationKey[]) {
	let storedValue: ValidationKey[] = initialKeys ? [...initialKeys] : [];
	const context = {
		globalState: {
			get: (_key: string, defaultValue: ValidationKey[]) => storedValue ?? defaultValue,
			update: async (_key: string, value: ValidationKey[]) => {
				storedValue = value;
			}
		}
	} as never;

	return {
		manager: new KeyManager(context),
		getStoredKeys: () => storedValue
	};
}

function createKeySetData(keys: Record<string, unknown>[]): string {
	return encodeToBase64(JSON.stringify({ keys }));
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

async function withJsonServer(routes: Record<string, MockResponse>, run: (baseUrl: string) => Promise<void>): Promise<void> {
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

	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()));
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
			server.close(error => {
				if (error) {
					reject(error);
					return;
				}
				resolve();
			});
		});
	}
}

const VALID_PUBLIC_PEM = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'pem' }).toString();

suite('Key Manager Selection and Editor Data', () => {
	test('getValidationMaterial should prioritize explicit override over JWT kid match', () => {
		const manager = createManager();
		const key: ValidationKey = {
			id: 'selection-override',
			name: 'Selection Override',
			source: KeySource.JWKSJson,
			keyData: createKeySetData([VALID_KEY_1, INVALID_KEY_3]),
			createdAt: Date.now()
		};

		const result = manager.getValidationMaterial(key, 'key1', 'kid:key3');
		assert.strictEqual(result.success, true);
		assert.strictEqual(result.data?.selectedKid, 'key3');
		assert.strictEqual(result.data?.selectedKeyRef, 'kid:key3');
		assert.strictEqual(result.data?.selectionReason, 'override');
	});

	test('getValidationMaterial should use kid match when no override is provided', () => {
		const manager = createManager();
		const key: ValidationKey = {
			id: 'selection-kid',
			name: 'Selection Kid Match',
			source: KeySource.JWKSJson,
			keyData: createKeySetData([VALID_KEY_1, INVALID_KEY_3]),
			createdAt: Date.now()
		};

		const result = manager.getValidationMaterial(key, 'key1');
		assert.strictEqual(result.success, true);
		assert.strictEqual(result.data?.selectedKid, 'key1');
		assert.strictEqual(result.data?.selectedKeyRef, 'kid:key1');
		assert.strictEqual(result.data?.selectionReason, 'kid-match');
	});

	test('getValidationMaterial should accept index-based override refs', () => {
		const manager = createManager();
		const key: ValidationKey = {
			id: 'selection-index-override',
			name: 'Selection Index Override',
			source: KeySource.JWKSJson,
			keyData: createKeySetData([
				{ kty: 'RSA', n: VALID_RSA_N, e: 'AQAB', use: 'sig', alg: 'RS256' },
				VALID_KEY_2
			]),
			createdAt: Date.now()
		};

		const result = manager.getValidationMaterial(key, undefined, 'index:1');
		assert.strictEqual(result.success, true);
		assert.strictEqual(result.data?.selectedKid, 'key2');
		assert.strictEqual(result.data?.selectedKeyRef, 'kid:key2');
		assert.strictEqual(result.data?.selectionReason, 'override');
	});

	test('getValidationMaterial should report missing kid matches when no fallback key is selected', () => {
		const manager = createManager();
		const key: ValidationKey = {
			id: 'selection-kid-missing',
			name: 'Selection Kid Missing',
			source: KeySource.JWKSJson,
			keyData: createKeySetData([VALID_KEY_1, VALID_KEY_2]),
			createdAt: Date.now()
		};

		const result = manager.getValidationMaterial(key, 'missing-kid');
		assert.strictEqual(result.success, false);
		assert.ok((result.error || '').includes('No key with kid "missing-kid"'));
	});

	test('getValidationMaterial should require override when JWT kid is missing for multi-key sets', () => {
		const manager = createManager();
		const key: ValidationKey = {
			id: 'selection-preferred',
			name: 'Selection Preferred',
			source: KeySource.JWKSJson,
			keyData: createKeySetData([VALID_KEY_1, VALID_KEY_2]),
			createdAt: Date.now()
		};

		const result = manager.getValidationMaterial(key);
		assert.strictEqual(result.success, false);
		assert.ok((result.error || '').includes('no fallback key is selected'));
	});

	test('getKeyEditorData should expose complete URL key set and selected preferred key', () => {
		const manager = createManager();
		const urlKey: URLValidationKey = {
			id: 'url-key-editor',
			name: 'URL Editor Data',
			source: KeySource.URL,
			url: 'https://example.com/jwks',
			refreshPeriod: RefreshPeriod.Weekly,
			lastFetchedAt: Date.now(),
			nextRefreshAt: Date.now() + 60000,
			keyData: createKeySetData([VALID_KEY_1, VALID_KEY_2]),
			createdAt: Date.now()
		};

		const editorData = manager.getKeyEditorData(urlKey);
		assert.strictEqual((editorData.claims.kid as string), 'key1');
		assert.strictEqual(editorData.availableKeyOptions?.length, 2);
		assert.ok((editorData.decodedKey || '').includes('BEGIN PUBLIC KEY'));
		const rawJson = editorData.rawJson ? JSON.parse(editorData.rawJson) : null;
		assert.ok(rawJson && Array.isArray(rawJson.keys));
		assert.strictEqual(rawJson.keys.length, 2);
	});

	test('getKeyEditorData should keep original raw JWKS JSON for jwks-json keys', () => {
		const manager = createManager();
		const rawJwksJson = JSON.stringify({ keys: [VALID_KEY_1, VALID_KEY_2] });
		const jwksKey: JWKSJsonValidationKey = {
			id: 'jwks-key-editor',
			name: 'JWKS Editor Data',
			source: KeySource.JWKSJson,
			rawJwksJson,
			keyData: createKeySetData([VALID_KEY_1, VALID_KEY_2]),
			createdAt: Date.now()
		};

		const editorData = manager.getKeyEditorData(jwksKey);
		assert.strictEqual(editorData.rawJson, rawJwksJson);
		assert.strictEqual((editorData.claims.kid as string), 'key1');
		assert.strictEqual(editorData.availableKeyOptions?.length, 2);
	});

	test('getKeyEditorData should expose fallback labels and refs when key metadata is missing', () => {
		const manager = createManager();
		const key: ValidationKey = {
			id: 'editor-fallback-labels',
			name: 'Editor Fallback Labels',
			source: KeySource.URL,
			keyData: createKeySetData([
				{ n: VALID_RSA_N, e: 'AQAB' },
				{ kty: 'RSA', kid: 'named-key', alg: 'RS256', n: VALID_RSA_N, e: 'AQAB' }
			]),
			url: 'https://example.com/jwks',
			refreshPeriod: RefreshPeriod.Daily,
			lastFetchedAt: Date.now(),
			nextRefreshAt: Date.now() + 60_000,
			createdAt: Date.now()
		} as URLValidationKey;

		const editorData = manager.getKeyEditorData(key);
		assert.strictEqual(editorData.availableKeyOptions?.[0].ref, 'index:0');
		assert.ok((editorData.availableKeyOptions?.[0].label || '').includes('kid=(none)'));
		assert.ok((editorData.availableKeyOptions?.[0].label || '').includes('kty=(unknown)'));
		assert.ok((editorData.availableKeyOptions?.[0].label || '').includes('alg=(unspecified)'));
		assert.ok((editorData.rawJson || '').includes('keys'));
	});

	test('manual key model should validate via the same viewer path as other key sources', async () => {
		const manager = createManager();
		const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

		const jose = await import('jose');
		const publicJwk = await jose.exportJWK(publicKey);
		const manualKid = 'manual-key-1';
		const manualJwk: Record<string, unknown> = {
			...publicJwk,
			alg: 'RS256',
			use: 'sig',
			kid: manualKid,
			typ: 'JWT'
		};

		const key: ValidationKey = {
			id: 'manual-viewer-path',
			name: 'Manual Viewer Path',
			source: KeySource.Manual,
			keyData: createKeySetData([manualJwk]),
			createdAt: Date.now()
		};

		const token = await new jose.SignJWT({ sub: 'alice' })
			.setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: manualKid })
			.setIssuedAt()
			.setExpirationTime('2h')
			.sign(privateKey);

		const material = manager.getValidationMaterial(key, manualKid);
		assert.strictEqual(material.success, true);
		assert.ok(material.data?.publicKey.includes('BEGIN PUBLIC KEY'));

		const validation = await validateJWTSignature(token, material.data?.publicKey || '');
		assert.strictEqual(validation.valid, true);
	});

	test('getKeyEditorData should preserve manual claims from stored key object', () => {
		const manager = createManager();
		const legacyManualObject = {
			...VALID_KEY_1,
			key: '-----BEGIN PUBLIC KEY-----\nlegacy\n-----END PUBLIC KEY-----',
			preferredKeyRef: 'kid:key1'
		};
		const key: ValidationKey = {
			id: 'manual-legacy-claims',
			name: 'Manual Legacy Claims',
			source: KeySource.Manual,
			keyData: encodeToBase64(JSON.stringify(legacyManualObject)),
			createdAt: Date.now()
		};

		const editorData = manager.getKeyEditorData(key);
		assert.strictEqual('preferredKeyRef' in editorData.claims, true);
	});

		test('getValidationMaterial should fall back to the only key when there is a single-key set', () => {
			const manager = createManager();
			const key: ValidationKey = {
				id: 'selection-single',
				name: 'Selection Single Key',
				source: KeySource.Manual,
				keyData: createKeySetData([VALID_KEY_1]),
				createdAt: Date.now()
			};

			const result = manager.getValidationMaterial(key);
			assert.strictEqual(result.success, true);
			assert.strictEqual(result.data?.selectionReason, 'single-key');
			assert.strictEqual(result.data?.selectedKid, 'key1');
		});

		test('getValidationMaterial should reject unusable selected keys', () => {
			const manager = createManager();
			const key: ValidationKey = {
				id: 'selection-invalid',
				name: 'Selection Invalid',
				source: KeySource.Manual,
				keyData: createKeySetData([{ kid: 'invalid-key' }]),
				createdAt: Date.now()
			};

			const result = manager.getValidationMaterial(key);
			assert.strictEqual(result.success, false);
			assert.ok((result.error || '').includes('not usable'));
		});

		test('getValidationMaterial should fall back to embedded PEM when JWK conversion fails', () => {
			const manager = createManager();
			const key: ValidationKey = {
				id: 'selection-embedded-pem',
				name: 'Selection Embedded PEM',
				source: KeySource.Manual,
				keyData: createKeySetData([{ kid: 'pem-key', key: VALID_PUBLIC_PEM }]),
				createdAt: Date.now()
			};

			const result = manager.getValidationMaterial(key, 'pem-key');
			assert.strictEqual(result.success, true);
			assert.strictEqual(result.data?.publicKey, VALID_PUBLIC_PEM);
		});

		test('getPublicKeyForValidation should fall back to decoded key data when validation material cannot be derived', () => {
			const manager = createManager();
			const key: ValidationKey = {
				id: 'selection-fallback',
				name: 'Selection Fallback',
				source: KeySource.Manual,
				keyData: encodeToBase64('plain-text-key'),
				createdAt: Date.now()
			};

			assert.strictEqual(manager.getPublicKeyForValidation(key), 'plain-text-key');
		});

		test('getPublicKeyForValidation should return derived public key when validation material succeeds', () => {
			const manager = createManager();
			const key: ValidationKey = {
				id: 'selection-success',
				name: 'Selection Success',
				source: KeySource.Manual,
				keyData: createKeySetData([VALID_KEY_1]),
				createdAt: Date.now()
			};

			assert.ok(manager.getPublicKeyForValidation(key).includes('BEGIN PUBLIC KEY'));
		});

		test('getKeyEditorData should return decoded content when stored data is not usable JSON', () => {
			const manager = createManager();
			const key: ValidationKey = {
				id: 'editor-invalid',
				name: 'Editor Invalid',
				source: KeySource.Manual,
				keyData: encodeToBase64('not-json'),
				createdAt: Date.now()
			};

			const editorData = manager.getKeyEditorData(key);
			assert.deepStrictEqual(editorData.claims, {});
			assert.strictEqual(editorData.decodedKey, 'not-json');
		});

		test('getKeyEditorData should fall back to the first key and empty decoded PEM when no sig key is marked', () => {
			const manager = createManager();
			const key: ValidationKey = {
				id: 'editor-first-key-fallback',
				name: 'Editor First Key Fallback',
				source: KeySource.Manual,
				keyData: createKeySetData([{ kid: 'first-key' }, { kid: 'second-key', use: 'enc' }]),
				createdAt: Date.now()
			};

			const editorData = manager.getKeyEditorData(key);
			assert.strictEqual(editorData.kid, 'first-key');
			assert.strictEqual(editorData.decodedKey, '');
			assert.strictEqual(editorData.rawJson, undefined);
		});
});

suite('Key Manager Operations', () => {
	test('addManualKey should persist a normalized manual key', async () => {
		const { manager, getStoredKeys } = createManagerWithContext();
		const result = await manager.addManualKey(
			'  Manual Key  ',
			VALID_PUBLIC_PEM.replaceAll('\n', '\r\n'),
			' RS256 ',
			' rsa ',
			{ kid: 'manual-1', n: VALID_RSA_N, e: 'AQAB', typ: 'JWT' },
			' description '
		);

		assert.strictEqual(result.success, true);
		assert.strictEqual(getStoredKeys().length, 1);
		assert.strictEqual(getStoredKeys()[0].name, 'Manual Key');
		assert.strictEqual(getStoredKeys()[0].description, 'description');
	});

	test('addManualKey should reject invalid manual key input', async () => {
		const { manager } = createManagerWithContext();
		assert.strictEqual((await manager.addManualKey('', VALID_PUBLIC_PEM)).success, false);
		assert.strictEqual((await manager.addManualKey('Manual', '')).success, false);
		assert.strictEqual((await manager.addManualKey('Manual', 'not-a-pem')).success, false);
		assert.strictEqual((await manager.addManualKey('Manual OCT', '', 'HS256', 'OCT', { kid: 'oct-1' })).success, false);
		assert.strictEqual((await manager.addManualKey('Manual OCT', 'nvCOlEaAhu6n5EiKOtZePbfZhRVna2PaRSfyN-jEYG0', 'HS256', 'OCT', { kid: 'oct-1' })).success, true);
		assert.strictEqual((await manager.addManualKey('Manual', VALID_PUBLIC_PEM, 'RS256', 'CUSTOM', { kid: 'manual-1' })).success, false);
		assert.strictEqual((await manager.addManualKey('Manual', VALID_PUBLIC_PEM, 'RS256', 'RSA', { e: 'bad+/value' })).success, false);
		assert.strictEqual((await manager.addManualKey('Manual', VALID_PUBLIC_PEM, 'RS256', 'RSA', { e: 'AQAB', n: 'bad+/value' })).success, false);
		assert.strictEqual((await manager.addManualKey('Manual', VALID_PUBLIC_PEM, 'RS256', 'RSA', undefined, 'x'.repeat(51))).success, false);
	});

	test('addJWKSJsonKey and updateJWKSJsonKey should validate and persist JSON input', async () => {
		const { manager, getStoredKeys } = createManagerWithContext();
		const addResult = await manager.addJWKSJsonKey('JWKS', JSON.stringify({ keys: [VALID_KEY_1, VALID_KEY_2] }), 'jwks');
		assert.strictEqual(addResult.success, true);
		assert.strictEqual(getStoredKeys().length, 1);

		const updateResult = await manager.updateJWKSJsonKey(getStoredKeys()[0].id, 'JWKS Updated', JSON.stringify({ keys: [VALID_KEY_2] }), 'updated');
		assert.strictEqual(updateResult.success, true);
		assert.strictEqual((getStoredKeys()[0] as JWKSJsonValidationKey).rawJwksJson, JSON.stringify({ keys: [VALID_KEY_2] }));

		assert.strictEqual((await manager.addJWKSJsonKey('', JSON.stringify({ keys: [] }))).success, false);
		assert.strictEqual((await manager.addJWKSJsonKey('Bad', 'not-json')).success, false);
		assert.strictEqual((await manager.updateJWKSJsonKey('missing', 'JWKS', JSON.stringify({ keys: [VALID_KEY_1] }))).success, false);
	});

	test('updateJWKSJsonKey should reject non-JWKS keys and invalid descriptions', async () => {
		const { manager, getStoredKeys } = createManagerWithContext();
		await manager.addManualKey('Manual', VALID_PUBLIC_PEM, 'RS256', 'RSA', { kid: 'manual-1', n: VALID_RSA_N, e: 'AQAB' });
		const manualId = getStoredKeys()[0].id;

		assert.strictEqual((await manager.updateJWKSJsonKey(manualId, 'Wrong', JSON.stringify({ keys: [VALID_KEY_1] }))).success, false);
		assert.strictEqual((await manager.updateJWKSJsonKey(manualId, 'Wrong', JSON.stringify({ keys: [VALID_KEY_1] }), 'x'.repeat(51))).success, false);
	});

	test('addURLKey and refreshURLKey should persist fetched JWKS content', async () => {
		await withJsonServer({
			'/.well-known/openid-configuration': { body: { jwks_uri: '__BASE__/.well-known/jwks.json' } },
			'/.well-known/jwks.json': { body: { keys: [VALID_KEY_1] } },
			'/refresh-jwks': { body: { keys: [VALID_KEY_2] } }
		}, async (baseUrl) => {
			const { manager, getStoredKeys } = createManagerWithContext();
			const addResult = await manager.addURLKey('Fetched URL Key', baseUrl, RefreshPeriod.Daily, 'url key');
			assert.strictEqual(addResult.success, true);
			assert.strictEqual(getStoredKeys().length, 1);
			const urlKeyId = getStoredKeys()[0].id;

			getStoredKeys()[0] = {
				...getStoredKeys()[0],
				url: `${baseUrl}/refresh-jwks`
			} as URLValidationKey;

			const refreshResult = await manager.refreshURLKey(urlKeyId);
			assert.strictEqual(refreshResult.success, true);
			assert.ok((refreshResult.key?.keyData || '').length > 0);
		});
	});

	test('addURLKey should reject invalid input and fetch failures', async () => {
		const { manager } = createManagerWithContext();
		assert.strictEqual((await manager.addURLKey('', 'https://example.com', RefreshPeriod.Daily)).success, false);
		assert.strictEqual((await manager.addURLKey('URL Key', '', RefreshPeriod.Daily)).success, false);
		assert.strictEqual((await manager.addURLKey('URL Key', 'https://example.com', RefreshPeriod.Daily, 'x'.repeat(51))).success, false);
		assert.strictEqual((await manager.addURLKey('URL Key', 'http://127.0.0.1:9', RefreshPeriod.Daily)).success, false);
	});

	test('addURLKey should reject fetched JWKS payloads with no object keys', async () => {
		await withJsonServer({
			'/.well-known/openid-configuration': { body: { jwks_uri: '__BASE__/.well-known/jwks.json' } },
			'/.well-known/jwks.json': { body: { keys: [1, 'bad', null] } }
		}, async (baseUrl) => {
			const { manager } = createManagerWithContext();
			const result = await manager.addURLKey('URL Key', baseUrl, RefreshPeriod.Daily);

			assert.strictEqual(result.success, false);
			assert.strictEqual(result.error, 'No suitable keys found in JWKS');
		});
	});

	test('refreshURLKey should handle missing, wrong-source, and failed-fetch cases', async () => {
		const { manager, getStoredKeys } = createManagerWithContext();
		assert.strictEqual((await manager.refreshURLKey('missing')).success, false);

		await manager.addManualKey('Manual', VALID_PUBLIC_PEM, 'RS256', 'RSA', { kid: 'manual-1', n: VALID_RSA_N, e: 'AQAB' });
		assert.strictEqual((await manager.refreshURLKey(getStoredKeys()[0].id)).success, false);

		const failingUrlKey: URLValidationKey = {
			id: 'failing-url',
			name: 'Failing URL',
			source: KeySource.URL,
			url: 'http://127.0.0.1:9',
			refreshPeriod: RefreshPeriod.Daily,
			keyData: createKeySetData([VALID_KEY_1]),
			createdAt: Date.now(),
			lastFetchedAt: Date.now(),
			nextRefreshAt: Date.now() - 1
		};
		const failureContext = createManagerWithContext([failingUrlKey]);
		assert.strictEqual((await failureContext.manager.refreshURLKey('failing-url')).success, false);
	});

	test('refreshURLKey should reject fetched JWKS payloads with no object keys', async () => {
		await withJsonServer({
			'/jwks-valid': { body: { keys: [VALID_KEY_1] } },
			'/jwks-empty-objects': { body: { keys: [1, 'bad', null] } }
		}, async (baseUrl) => {
			const { manager, getStoredKeys } = createManagerWithContext();
			const addResult = await manager.addURLKey('URL Key', `${baseUrl}/jwks-valid`, RefreshPeriod.Daily);
			assert.strictEqual(addResult.success, true);

			getStoredKeys()[0] = {
				...getStoredKeys()[0],
				url: `${baseUrl}/jwks-empty-objects`
			} as URLValidationKey;

			const refreshResult = await manager.refreshURLKey(getStoredKeys()[0].id);
			assert.strictEqual(refreshResult.success, false);
			assert.strictEqual(refreshResult.error, 'No suitable keys found in JWKS');
		});
	});

	test('refreshURLKey should handle storage update misses and thrown storage errors', async () => {
		await withJsonServer({
			'/jwks': { body: { keys: [VALID_KEY_1] } }
		}, async (baseUrl) => {
			const manager = createManager();
			const urlKey: URLValidationKey = {
				id: 'url-refresh-stub',
				name: 'URL Refresh Stub',
				source: KeySource.URL,
				url: `${baseUrl}/jwks`,
				refreshPeriod: RefreshPeriod.Daily,
				keyData: createKeySetData([VALID_KEY_2]),
				createdAt: Date.now(),
				lastFetchedAt: Date.now(),
				nextRefreshAt: Date.now() - 1
			};

			(manager as any).storageManager = {
				getKeyById: async () => urlKey,
				updateURLKey: async () => undefined
			};
			const missingUpdateResult = await manager.refreshURLKey('url-refresh-stub');
			assert.strictEqual(missingUpdateResult.success, false);
			assert.ok((missingUpdateResult.error || '').includes('Failed to update key'));

			(manager as any).storageManager = {
				getKeyById: async () => {
					throw new Error('refresh storage failure');
				}
			};
			const thrownResult = await manager.refreshURLKey('url-refresh-stub');
			assert.strictEqual(thrownResult.success, false);
			assert.ok((thrownResult.error || '').includes('refresh storage failure'));
		});
	});

	test('getKeyAndRefreshIfNeeded should return manual keys, cached URL keys, and warnings on refresh failure', async () => {
		const manualContext = createManagerWithContext();
		const addManual = await manualContext.manager.addManualKey('Manual', VALID_PUBLIC_PEM, 'RS256', 'RSA', { kid: 'manual-1', n: VALID_RSA_N, e: 'AQAB' });
		const manualId = manualContext.getStoredKeys()[0].id;
		assert.strictEqual(addManual.success, true);
		assert.strictEqual((await manualContext.manager.getKeyAndRefreshIfNeeded(manualId)).success, true);

		const cachedUrlKey: URLValidationKey = {
			id: 'cached-url',
			name: 'Cached URL',
			source: KeySource.URL,
			url: 'http://127.0.0.1:9',
			refreshPeriod: RefreshPeriod.Daily,
			keyData: createKeySetData([VALID_KEY_1]),
			createdAt: Date.now(),
			lastFetchedAt: Date.now(),
			nextRefreshAt: Date.now() + 60_000
		};
		const cachedContext = createManagerWithContext([cachedUrlKey]);
		assert.strictEqual((await cachedContext.manager.getKeyAndRefreshIfNeeded('cached-url')).success, true);

		const expiredUrlKey: URLValidationKey = { ...cachedUrlKey, id: 'expired-url', nextRefreshAt: Date.now() - 1 };
		const expiredContext = createManagerWithContext([expiredUrlKey]);
		const expiredResult = await expiredContext.manager.getKeyAndRefreshIfNeeded('expired-url');
		assert.strictEqual(expiredResult.success, true);
		assert.ok((expiredResult.error || '').includes('Using cached key'));
		assert.strictEqual((await expiredContext.manager.getKeyAndRefreshIfNeeded('missing')).success, false);
	});

	test('updateManualKey, updateKeyName, updateURLKeySettings, and deleteKey should handle success and validation errors', async () => {
		const { manager, getStoredKeys } = createManagerWithContext();
		await manager.addManualKey('Manual', VALID_PUBLIC_PEM, 'RS256', 'RSA', { kid: 'manual-1', n: VALID_RSA_N, e: 'AQAB' });
		const manualId = getStoredKeys()[0].id;

		assert.strictEqual((await manager.updateManualKey(manualId, 'Manual Updated', VALID_PUBLIC_PEM, 'ES256', 'EC', { kid: 'manual-2', e: 'AQAB' }, 'updated')).success, true);
		assert.strictEqual((await manager.updateManualKey(manualId, '', VALID_PUBLIC_PEM)).success, false);
		assert.strictEqual((await manager.updateManualKey(manualId, 'Manual Updated', 'bad pem')).success, false);
		assert.strictEqual((await manager.updateManualKey(manualId, 'Manual Updated', VALID_PUBLIC_PEM, 'RS256', 'CUSTOM', { kid: 'manual-2' })).success, false);
		assert.strictEqual((await manager.updateManualKey('missing', 'Manual Updated', VALID_PUBLIC_PEM)).success, false);

		assert.strictEqual((await manager.updateKeyName(manualId, 'Renamed', 'desc')).success, true);
		assert.strictEqual((await manager.updateKeyName(manualId, '')).success, false);
		assert.strictEqual((await manager.updateKeyName(manualId, 'Renamed', 'x'.repeat(51))).success, false);
		assert.strictEqual((await manager.updateKeyName('missing', 'Renamed')).success, false);

		const urlKey: URLValidationKey = {
			id: 'url-settings',
			name: 'URL Settings',
			source: KeySource.URL,
			url: 'https://example.com/jwks',
			refreshPeriod: RefreshPeriod.Daily,
			keyData: createKeySetData([VALID_KEY_1]),
			createdAt: Date.now(),
			lastFetchedAt: Date.now(),
			nextRefreshAt: Date.now() + 60_000
		};
		const urlContext = createManagerWithContext([urlKey]);
		assert.strictEqual((await urlContext.manager.updateURLKeySettings('url-settings', 'Updated URL', RefreshPeriod.Monthly, 'desc')).success, true);
		assert.strictEqual((await urlContext.manager.updateURLKeySettings('url-settings', '', RefreshPeriod.Daily)).success, false);
		assert.strictEqual((await urlContext.manager.updateURLKeySettings('url-settings', 'Updated URL', RefreshPeriod.Daily, 'x'.repeat(51))).success, false);
		assert.strictEqual((await manager.updateURLKeySettings(manualId, 'Bad', RefreshPeriod.Daily)).success, false);
		assert.strictEqual((await urlContext.manager.updateURLKeySettings('missing', 'Updated URL', RefreshPeriod.Daily)).success, false);

		assert.strictEqual(await manager.deleteKey(manualId), true);
		assert.strictEqual(await manager.deleteKey(manualId), false);
	});

	test('updateKeyName should surface storage failures', async () => {
		const manager = createManager();
		(manager as any).storageManager = {
			updateKeyName: async () => {
				throw new Error('storage failure');
			}
		};

		const result = await manager.updateKeyName('key-id', 'Renamed');
		assert.strictEqual(result.success, false);
		assert.ok((result.error || '').includes('storage failure'));
	});

	test('updateManualKey should handle invalid claims, storage misses, and thrown storage errors', async () => {
		const manager = createManager();
		assert.strictEqual(
			(await manager.updateManualKey('key-id', 'Manual', VALID_PUBLIC_PEM, 'RS256', 'RSA', { e: 'AQAB', n: VALID_RSA_N }, 'x'.repeat(51))).success,
			false
		);
		assert.strictEqual(
			(await manager.updateManualKey('key-id', 'Manual', VALID_PUBLIC_PEM, 'RS256', 'RSA', { e: 'bad+/value' })).success,
			false
		);

		(manager as any).storageManager = {
			updateManualKey: async () => undefined
		};
		const missingResult = await manager.updateManualKey('key-id', 'Manual', VALID_PUBLIC_PEM, 'RS256', 'RSA', { e: 'AQAB', n: VALID_RSA_N });
		assert.strictEqual(missingResult.success, false);
		assert.ok((missingResult.error || '').includes('cannot be updated'));

		(manager as any).storageManager = {
			updateManualKey: async () => {
				throw new Error('manual update failure');
			}
		};
		const thrownResult = await manager.updateManualKey('key-id', 'Manual', VALID_PUBLIC_PEM, 'RS256', 'RSA', { e: 'AQAB', n: VALID_RSA_N });
		assert.strictEqual(thrownResult.success, false);
		assert.ok((thrownResult.error || '').includes('manual update failure'));
	});

	test('updateURLKeySettings should handle storage miss after lookup and thrown storage errors', async () => {
		const manager = createManager();
		const urlKey: URLValidationKey = {
			id: 'url-settings-stub',
			name: 'URL Settings Stub',
			source: KeySource.URL,
			url: 'https://example.com/jwks',
			refreshPeriod: RefreshPeriod.Daily,
			keyData: createKeySetData([VALID_KEY_1]),
			createdAt: Date.now(),
			lastFetchedAt: Date.now(),
			nextRefreshAt: Date.now() + 60_000
		};

		(manager as any).storageManager = {
			getKeyById: async () => urlKey,
			updateURLKeySettings: async () => undefined
		};
		const missingResult = await manager.updateURLKeySettings('url-settings-stub', 'Updated URL', RefreshPeriod.Weekly);
		assert.strictEqual(missingResult.success, false);
		assert.ok((missingResult.error || '').includes('cannot be updated'));

		(manager as any).storageManager = {
			getKeyById: async () => urlKey,
			updateURLKeySettings: async () => {
				throw new Error('update failure');
			}
		};
		const thrownResult = await manager.updateURLKeySettings('url-settings-stub', 'Updated URL', RefreshPeriod.Weekly);
		assert.strictEqual(thrownResult.success, false);
		assert.ok((thrownResult.error || '').includes('update failure'));
	});

	test('refreshAllExpiredKeys should refresh only expired URL keys', async () => {
		await withJsonServer({
			'/expired-jwks': { body: { keys: [VALID_KEY_2] } },
			'/fresh-jwks': { body: { keys: [VALID_KEY_1] } }
		}, async (baseUrl) => {
			const expiredKey: URLValidationKey = {
				id: 'expired',
				name: 'Expired',
				source: KeySource.URL,
				url: `${baseUrl}/expired-jwks`,
				refreshPeriod: RefreshPeriod.Daily,
				keyData: createKeySetData([VALID_KEY_1]),
				createdAt: Date.now(),
				lastFetchedAt: Date.now(),
				nextRefreshAt: Date.now() - 1
			};
			const freshKey: URLValidationKey = {
				id: 'fresh',
				name: 'Fresh',
				source: KeySource.URL,
				url: `${baseUrl}/fresh-jwks`,
				refreshPeriod: RefreshPeriod.Daily,
				keyData: createKeySetData([VALID_KEY_1]),
				createdAt: Date.now(),
				lastFetchedAt: Date.now(),
				nextRefreshAt: Date.now() + 60_000
			};
			const originalExpiredKeyData = expiredKey.keyData;
			const { manager, getStoredKeys } = createManagerWithContext([expiredKey, freshKey]);
			await manager.refreshAllExpiredKeys();
			assert.notStrictEqual(getStoredKeys()[0].keyData, originalExpiredKeyData);
			assert.strictEqual(getStoredKeys()[1].keyData, freshKey.keyData);
		});
	});

	test('getKeyAndRefreshIfNeeded should return refreshed key data when refresh succeeds and surface lookup exceptions', async () => {
		await withJsonServer({
			'/fresh-jwks': { body: { keys: [VALID_KEY_2] } }
		}, async (baseUrl) => {
			const expiredKey: URLValidationKey = {
				id: 'expired-success',
				name: 'Expired Success',
				source: KeySource.URL,
				url: `${baseUrl}/fresh-jwks`,
				refreshPeriod: RefreshPeriod.Daily,
				keyData: createKeySetData([VALID_KEY_1]),
				createdAt: Date.now(),
				lastFetchedAt: Date.now(),
				nextRefreshAt: Date.now() - 1
			};
			const originalKeyData = expiredKey.keyData;
			const successContext = createManagerWithContext([expiredKey]);
			const refreshed = await successContext.manager.getKeyAndRefreshIfNeeded('expired-success');
			assert.strictEqual(refreshed.success, true);
			assert.strictEqual(refreshed.error, undefined);
			assert.notStrictEqual(refreshed.key?.keyData, originalKeyData);
		});

		const manager = createManager();
		(manager as any).storageManager = {
			getKeyById: async () => {
				throw new Error('lookup failure');
			}
		};
		const failureResult = await manager.getKeyAndRefreshIfNeeded('broken');
		assert.strictEqual(failureResult.success, false);
		assert.ok((failureResult.error || '').includes('lookup failure'));
	});
});
