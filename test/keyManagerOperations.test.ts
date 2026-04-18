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

function createManager(): KeyManager {
	return new KeyManager({} as never);
}

function createManagerWithDependencies(dependencies: ConstructorParameters<typeof KeyManager>[1]): KeyManager {
	return new KeyManager({} as never, dependencies);
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

suite('Key Manager Operations', () => {
	test('getAllKeys and getKeyById should expose stored keys through the manager', async () => {
		const manualKey: ValidationKey = {
			id: 'stored-manual',
			name: 'Stored Manual',
			source: KeySource.Manual,
			keyData: createKeySetData([VALID_KEY_1]),
			createdAt: Date.now()
		};
		const urlKey: URLValidationKey = {
			id: 'stored-url',
			name: 'Stored URL',
			source: KeySource.URL,
			url: 'https://example.com/jwks',
			refreshPeriod: RefreshPeriod.Daily,
			lastFetchedAt: Date.now(),
			nextRefreshAt: Date.now() + 60_000,
			keyData: createKeySetData([VALID_KEY_2]),
			createdAt: Date.now()
		};
		const { manager } = createManagerWithContext([manualKey, urlKey]);

		const allKeys = await manager.getAllKeys();
		const foundKey = await manager.getKeyById('stored-url');
		const missingKey = await manager.getKeyById('missing');

		assert.strictEqual(allKeys.length, 2);
		assert.strictEqual(foundKey?.id, 'stored-url');
		assert.strictEqual(missingKey, undefined);
	});

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
		assert.strictEqual((await manager.addManualKey('Manual', '-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----')).success, false);
		assert.strictEqual((await manager.addManualKey('Manual', VALID_PUBLIC_PEM, 'RS256', 'RSA', { e: 'bad+/value' })).success, false);
		assert.strictEqual((await manager.addManualKey('Manual', VALID_PUBLIC_PEM, 'RS256', 'RSA', { e: 'AQAB', n: 'bad+/value' })).success, false);
		assert.strictEqual((await manager.addManualKey('Manual', VALID_PUBLIC_PEM, 'RS256', 'RSA', undefined, 'x'.repeat(51))).success, false);
	});

	test('addManualKey should accept alternate PEM headers and normalize blank claims to defaults', async () => {
		const { manager, getStoredKeys } = createManagerWithContext();
		const rsaPem = '-----BEGIN RSA PUBLIC KEY-----\nQUJD\n-----END RSA PUBLIC KEY-----';
		const ecPem = '-----BEGIN EC PUBLIC KEY-----\nQUJD\n-----END EC PUBLIC KEY-----';

		const rsaResult = await manager.addManualKey('RSA Header', rsaPem, ' RS256 ', ' rsa ', {
			kid: '   ',
			alg: '   ',
			use: '   ',
			typ: '   ',
			e: '   '
		});
		const ecResult = await manager.addManualKey('EC Header', ecPem, 'ES256', 'ec');

		assert.strictEqual(rsaResult.success, true);
		assert.strictEqual(ecResult.success, true);
		const decodedFirst = JSON.parse(Buffer.from(getStoredKeys()[0].keyData, 'base64').toString('utf8')) as { keys: Array<Record<string, string>> };
		assert.strictEqual(decodedFirst.keys[0].kid, 'key1');
		assert.strictEqual(decodedFirst.keys[0].alg, 'RS256');
		assert.strictEqual(decodedFirst.keys[0].use, 'sig');
		assert.strictEqual(decodedFirst.keys[0].typ, 'JWT');
		assert.strictEqual(decodedFirst.keys[0].e, 'AQAB');
	});

	test('addManualKey should surface storage failures through injected dependencies', async () => {
		const manager = createManagerWithDependencies({
			storageManager: {
				addManualKey: async () => {
					throw new Error('manual add failure');
				}
			} as never
		});

		const result = await manager.addManualKey('Manual', VALID_PUBLIC_PEM, 'RS256', 'RSA', { kid: 'manual-1', n: VALID_RSA_N, e: 'AQAB' });
		assert.strictEqual(result.success, false);
		assert.ok((result.error || '').includes('manual add failure'));
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
		assert.strictEqual((await manager.addJWKSJsonKey('Bad', JSON.stringify([]))).success, false);
		assert.strictEqual((await manager.addJWKSJsonKey('Bad', JSON.stringify({}))).success, false);
		assert.strictEqual((await manager.addJWKSJsonKey('Bad', JSON.stringify({ keys: [1, 2, 3] }))).success, false);
		assert.strictEqual((await manager.addJWKSJsonKey('Bad', JSON.stringify({ keys: [VALID_KEY_1] }), 'x'.repeat(51))).success, false);
		assert.strictEqual((await manager.updateJWKSJsonKey('missing', 'JWKS', JSON.stringify({ keys: [VALID_KEY_1] }))).success, false);
	});

	test('addJWKSJsonKey should surface storage failures', async () => {
		const manager = createManager();
		(manager as any).storageManager = {
			addJWKSJsonKey: async () => {
				throw new Error('add jwks failure');
			}
		};

		const result = await manager.addJWKSJsonKey('JWKS', JSON.stringify({ keys: [VALID_KEY_1] }));
		assert.strictEqual(result.success, false);
		assert.ok((result.error || '').includes('add jwks failure'));
	});

	test('updateJWKSJsonKey should reject non-JWKS keys and invalid descriptions', async () => {
		const { manager, getStoredKeys } = createManagerWithContext();
		assert.strictEqual((await manager.updateJWKSJsonKey('missing', '', JSON.stringify({ keys: [VALID_KEY_1] }))).success, false);
		await manager.addManualKey('Manual', VALID_PUBLIC_PEM, 'RS256', 'RSA', { kid: 'manual-1', n: VALID_RSA_N, e: 'AQAB' });
		const manualId = getStoredKeys()[0].id;

		assert.strictEqual((await manager.updateJWKSJsonKey(manualId, 'Wrong', JSON.stringify({ keys: [VALID_KEY_1] }))).success, false);
		assert.strictEqual((await manager.updateJWKSJsonKey(manualId, 'Wrong', JSON.stringify({ keys: [VALID_KEY_1] }), 'x'.repeat(51))).success, false);
		const { manager: jsonManager, getStoredKeys: getJsonKeys } = createManagerWithContext();
		await jsonManager.addJWKSJsonKey('JWKS', JSON.stringify({ keys: [VALID_KEY_1] }));
		const jsonId = getJsonKeys()[0].id;
		assert.strictEqual((await jsonManager.updateJWKSJsonKey(jsonId, 'Wrong', JSON.stringify([]))).success, false);
		assert.strictEqual((await jsonManager.updateJWKSJsonKey(jsonId, 'Wrong', JSON.stringify({}))).success, false);
		assert.strictEqual((await jsonManager.updateJWKSJsonKey(jsonId, 'Wrong', JSON.stringify({ keys: [1, 2] }))).success, false);
	});

	test('updateJWKSJsonKey should handle storage update misses and thrown storage errors', async () => {
		const manager = createManager();
		const jwksKey: JWKSJsonValidationKey = {
			id: 'jwks-update-stub',
			name: 'JWKS Update Stub',
			source: KeySource.JWKSJson,
			rawJwksJson: JSON.stringify({ keys: [VALID_KEY_1] }),
			keyData: createKeySetData([VALID_KEY_1]),
			createdAt: Date.now()
		};

		(manager as any).storageManager = {
			getKeyById: async () => jwksKey,
			updateJWKSJsonKey: async () => undefined
		};
		const missingResult = await manager.updateJWKSJsonKey('jwks-update-stub', 'Updated', JSON.stringify({ keys: [VALID_KEY_2] }));
		assert.strictEqual(missingResult.success, false);
		assert.ok((missingResult.error || '').includes('cannot be updated'));

		(manager as any).storageManager = {
			getKeyById: async () => jwksKey,
			updateJWKSJsonKey: async () => {
				throw new Error('jwks update failure');
			}
		};
		const thrownResult = await manager.updateJWKSJsonKey('jwks-update-stub', 'Updated', JSON.stringify({ keys: [VALID_KEY_2] }));
		assert.strictEqual(thrownResult.success, false);
		assert.ok((thrownResult.error || '').includes('jwks update failure'));
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

	test('addURLKey should reject JWKS responses that contain no object keys', async () => {
		await withJsonServer({
			'/non-object-jwks': { body: { keys: [1, 2, 3] } }
		}, async (baseUrl) => {
			const { manager } = createManagerWithContext();
			const result = await manager.addURLKey('URL Key', `${baseUrl}/non-object-jwks`, RefreshPeriod.Daily);
			assert.strictEqual(result.success, false);
			assert.ok((result.error || '').includes('No suitable keys found'));
		});
	});

	test('addURLKey should surface thrown fetch errors through injected dependencies', async () => {
		const manager = createManagerWithDependencies({
			fetchKeys: async () => {
				throw new Error('url add fetch failure');
			}
		});

		const result = await manager.addURLKey('URL Key', 'https://example.com/jwks', RefreshPeriod.Daily);
		assert.strictEqual(result.success, false);
		assert.ok((result.error || '').includes('url add fetch failure'));
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

	test('refreshURLKey should reject JWKS responses that contain no object keys', async () => {
		await withJsonServer({
			'/non-object-jwks': { body: { keys: [1, 2, 3] } }
		}, async (baseUrl) => {
			const urlKey: URLValidationKey = {
				id: 'non-object-refresh',
				name: 'Non Object Refresh',
				source: KeySource.URL,
				url: `${baseUrl}/non-object-jwks`,
				refreshPeriod: RefreshPeriod.Daily,
				keyData: createKeySetData([VALID_KEY_1]),
				createdAt: Date.now(),
				lastFetchedAt: Date.now(),
				nextRefreshAt: Date.now() - 1
			};
			const { manager } = createManagerWithContext([urlKey]);
			const result = await manager.refreshURLKey('non-object-refresh');
			assert.strictEqual(result.success, false);
			assert.ok((result.error || '').includes('No suitable keys found'));
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