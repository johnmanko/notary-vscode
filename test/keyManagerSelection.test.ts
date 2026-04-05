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

function createKeySetData(keys: Record<string, unknown>[]): string {
	return encodeToBase64(JSON.stringify({ keys }));
}

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
		assert.strictEqual(result.success, false);
		assert.ok(result.error?.includes('Selected key is not usable for validation'));
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

	test('getKeyEditorData should not expose preferredKeyRef in manual claims', () => {
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
		assert.strictEqual('preferredKeyRef' in editorData.claims, false);
	});
});
