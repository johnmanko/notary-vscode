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
import { JWKSJsonValidationKey, KeySource, RefreshPeriod, URLValidationKey, ValidationKey } from '../src/types/keyManagement';
import {
	buildJwksJson,
	buildKeyEditorData,
	ecHandler,
	getErrorMessage,
	isSupportedManualKty,
	getValidationMaterialFromDecoded,
	normalizeManualClaims,
	octHandler,
	okpHandler,
	parseStoredJson,
	parseJWKSJsonInput,
	resolveKeyByRef,
	rsaHandler,
	validateManualPemInput,
	validateManualClaims
} from '../src/utils/keyManagerHelpers';
import { encodeToBase64 } from '../src/utils/keyStorage';

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

const VALID_OCT_KEY: Record<string, unknown> = {
	kty: 'oct',
	k: 'abc_DEF-123',
	kid: 'oct-key-1',
	alg: 'HS256'
};

const VALID_OKP_KEY: Record<string, unknown> = {
	kty: 'OKP',
	crv: 'Ed25519',
	kid: 'example-okp-key-1',
	use: 'sig',
	alg: 'EdDSA',
	x: 'y3XQ-VuL7Q0LCSKgskZOkVu8g3gC17ZGXm5uj8xt4nQ'
};

const VALID_PUBLIC_PEM = [
	'-----BEGIN PUBLIC KEY-----',
	'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKf5nF4rAqvHn8Yv9eL9v2v6xD4v7wQx',
	'UvE7h6uY8nqgEv1ru8nD4yl5K5L9xLzAr72Xd1LSeX776BF3nf6tDrkCAwEAAQ==',
	'-----END PUBLIC KEY-----'
].join('\n');

function createKeySetData(keys: Record<string, unknown>[]): string {
	return encodeToBase64(JSON.stringify({ keys }));
}

function createDecodedKeySet(keys: Record<string, unknown>[]): string {
	return JSON.stringify({ keys });
}

suite('Key Manager Helpers', () => {
	test('normalizeManualClaims should preserve RSA defaults', () => {
		const claims = normalizeManualClaims('RS256', 'RSA', {});
		assert.strictEqual(claims.kty, 'RSA');
		assert.strictEqual(claims.e, 'AQAB');
		assert.strictEqual(claims.use, 'sig');
		assert.strictEqual(claims.alg, 'RS256');
		assert.strictEqual(claims.kid, 'key1');
		assert.strictEqual(claims.typ, 'JWT');
	});

	test('normalizeManualClaims should preserve non-RSA fields without injecting RSA claims', () => {
		const claims = normalizeManualClaims('ES256', 'EC', {
			crv: 'P-256',
			x: 'abc_DEF-123',
			y: 'xyz_DEF-456',
			kid: 'ec-key'
		});

		assert.strictEqual(claims.kty, 'EC');
		assert.strictEqual(claims.crv, 'P-256');
		assert.strictEqual(claims.x, 'abc_DEF-123');
		assert.strictEqual(claims.y, 'xyz_DEF-456');
		assert.strictEqual(claims.e, undefined);
		assert.strictEqual(claims.n, undefined);
	});

	test('normalizeManualClaims should route OKP and oct claims through their own shapes', () => {
		const okpClaims = normalizeManualClaims('EdDSA', 'OKP', { crv: 'Ed25519', x: 'abc_DEF-123' });
		const octClaims = normalizeManualClaims('HS256', 'oct', { k: 'abc_DEF-123' });

		assert.strictEqual(okpClaims.kty, 'OKP');
		assert.strictEqual(okpClaims.crv, 'Ed25519');
		assert.strictEqual(okpClaims.x, 'abc_DEF-123');
		assert.strictEqual(octClaims.kty, 'oct');
		assert.strictEqual(octClaims.k, 'abc_DEF-123');
	});

	test('validateManualClaims should keep RSA validation isolated', () => {
		assert.strictEqual(validateManualClaims({ kty: 'RSA', e: 'AQAB', n: VALID_RSA_N }).valid, true);
		assert.strictEqual(validateManualClaims({ kty: 'RSA', e: 'bad+/value' }).valid, false);
		assert.strictEqual(validateManualClaims({ kty: 'EC', x: 'abc_DEF-123', y: 'xyz_DEF-456' }).valid, true);
		assert.strictEqual(validateManualClaims({ kty: 'EC', x: 'bad+/value' }).valid, false);
		assert.strictEqual(validateManualClaims({ kty: 'CUSTOM', anything: 'goes' }).valid, false);
	});

	test('normalizeManualClaims should strip unsupported custom claims', () => {
		const claims = normalizeManualClaims('RS256', 'RSA', { kty: 'RSA', alg: 'RS256', kid: 'key1', e: 'AQAB', n: VALID_RSA_N, issuer: 'custom' });
		assert.strictEqual(claims.issuer, undefined);
		assert.strictEqual(claims.kty, 'RSA');
	});

	test('isSupportedManualKty should only accept supported JWT validation key types', () => {
		assert.strictEqual(isSupportedManualKty('RSA'), true);
		assert.strictEqual(isSupportedManualKty('ec'), true);
		assert.strictEqual(isSupportedManualKty('CUSTOM'), false);
	});

	test('parseJWKSJsonInput should reject malformed roots and filter non-object keys', () => {
		assert.strictEqual(parseJWKSJsonInput('').success, false);
		assert.strictEqual(parseJWKSJsonInput(JSON.stringify([])).success, false);
		assert.strictEqual(parseJWKSJsonInput(JSON.stringify({})).success, false);

		const parsed = parseJWKSJsonInput(JSON.stringify({ keys: [1, VALID_KEY_1, 'two', VALID_KEY_2] }));
		assert.strictEqual(parsed.success, true);
		assert.strictEqual(parsed.jwkObjects?.length, 2);
		assert.strictEqual(parsed.selectedJwk?.kid, 'key1');
	});

		test('buildJwksJson should produce parseable canonical JWKS JSON', () => {
			const jwksJson = buildJwksJson([VALID_KEY_1, VALID_KEY_2]);
			const parsed = parseJWKSJsonInput(jwksJson);

			assert.strictEqual(parsed.success, true);
			assert.strictEqual(parsed.jwkObjects?.length, 2);
			assert.strictEqual(parsed.selectedJwk?.kid, 'key1');
			assert.strictEqual(jwksJson, JSON.stringify({ keys: [VALID_KEY_1, VALID_KEY_2] }));
		});

	test('helper guards should cover empty PEM, non-object JSON, and invalid refs', () => {
		const pemValidation = validateManualPemInput('   ');
		assert.strictEqual(pemValidation.valid, false);
		assert.ok((pemValidation.error || '').includes('Public key is required'));

		assert.strictEqual(parseStoredJson(JSON.stringify(['not-an-object'])), null);
		assert.strictEqual(resolveKeyByRef([VALID_KEY_1], 'index:9'), null);
		assert.strictEqual(resolveKeyByRef([VALID_KEY_1], 'bogus-ref'), null);
	});

	test('getErrorMessage should handle Error and non-Error throws', () => {
		assert.strictEqual(getErrorMessage(new Error('boom'), 'fallback'), 'boom');
		assert.strictEqual(getErrorMessage('boom', 'fallback'), 'fallback');
	});

	test('getValidationMaterialFromDecoded should prefer override and preserve embedded PEM fallback', () => {
		const overrideResult = getValidationMaterialFromDecoded(createDecodedKeySet([VALID_KEY_1, VALID_KEY_2]), 'key1', 'kid:key2');
		assert.strictEqual(overrideResult.success, true);
		assert.strictEqual(overrideResult.data?.selectedKid, 'key2');
		assert.strictEqual(overrideResult.data?.selectionReason, 'override');

		const pemResult = getValidationMaterialFromDecoded(createDecodedKeySet([{ kid: 'pem-key', key: VALID_PUBLIC_PEM }]), 'pem-key');
		assert.strictEqual(pemResult.success, true);
		assert.strictEqual(pemResult.data?.publicKey, VALID_PUBLIC_PEM);
	});

	test('getValidationMaterialFromDecoded should reject missing kid fallback for multi-key sets', () => {
		const result = getValidationMaterialFromDecoded(createDecodedKeySet([VALID_KEY_1, VALID_KEY_2]), 'missing-kid');
		assert.strictEqual(result.success, false);
		assert.ok((result.error || '').includes('No key with kid'));
	});

	test('getValidationMaterialFromDecoded should return oct JWK JSON for symmetric validation', () => {
		const result = getValidationMaterialFromDecoded(createDecodedKeySet([VALID_OCT_KEY]), 'oct-key-1');
		assert.strictEqual(result.success, true);
		assert.strictEqual(result.data?.publicKey, JSON.stringify(VALID_OCT_KEY));
	});

	test('buildKeyEditorData should preserve URL and JWKS raw JSON sources', () => {
		const urlKey: URLValidationKey = {
			id: 'url-editor-helper',
			name: 'URL Editor Helper',
			source: KeySource.URL,
			url: 'https://example.com/jwks',
			refreshPeriod: RefreshPeriod.Daily,
			lastFetchedAt: Date.now(),
			nextRefreshAt: Date.now() + 60_000,
			keyData: createKeySetData([VALID_KEY_1, VALID_KEY_2]),
			createdAt: Date.now()
		};
		const jwksKey: JWKSJsonValidationKey = {
			id: 'jwks-editor-helper',
			name: 'JWKS Editor Helper',
			source: KeySource.JWKSJson,
			rawJwksJson: JSON.stringify({ keys: [VALID_KEY_1, VALID_KEY_2] }),
			keyData: createKeySetData([VALID_KEY_1, VALID_KEY_2]),
			createdAt: Date.now()
		};
		const invalidKey: ValidationKey = {
			id: 'invalid-editor-helper',
			name: 'Invalid Editor Helper',
			source: KeySource.Manual,
			keyData: encodeToBase64('not-json'),
			createdAt: Date.now()
		};

		const urlData = buildKeyEditorData(urlKey, Buffer.from(urlKey.keyData, 'base64').toString('utf8'));
		const jwksData = buildKeyEditorData(jwksKey, Buffer.from(jwksKey.keyData, 'base64').toString('utf8'));
		const invalidData = buildKeyEditorData(invalidKey, 'not-json');

		assert.ok((urlData.rawJson || '').includes('keys'));
		assert.strictEqual(jwksData.rawJson, jwksKey.rawJwksJson);
		assert.deepStrictEqual(invalidData.claims, {});
		assert.strictEqual(invalidData.decodedKey, 'not-json');
	});

	test('buildKeyEditorData should export PEM for OKP JWKs', () => {
		const jwksKey: JWKSJsonValidationKey = {
			id: 'jwks-okp-editor-helper',
			name: 'JWKS OKP Editor Helper',
			source: KeySource.JWKSJson,
			rawJwksJson: JSON.stringify({ keys: [VALID_OKP_KEY] }),
			keyData: createKeySetData([VALID_OKP_KEY]),
			createdAt: Date.now()
		};

		const jwksData = buildKeyEditorData(jwksKey, Buffer.from(jwksKey.keyData, 'base64').toString('utf8'));

		assert.strictEqual(jwksData.claims.kty, 'OKP');
		assert.strictEqual(jwksData.decodedKey, [
			'-----BEGIN PUBLIC KEY-----',
			'MCowBQYDK2VwAyEAy3XQ+VuL7Q0LCSKgskZOkVu8g3gC17ZGXm5uj8xt4nQ=',
			'-----END PUBLIC KEY-----',
			''
		].join('\n'));
	});
});

suite('KtyHandler — per-handler isolation', () => {
	test('rsaHandler metadata is correct', () => {
		assert.strictEqual(rsaHandler.kty, 'RSA');
		assert.strictEqual(rsaHandler.defaultAlgorithm, 'RS256');
	});

	test('rsaHandler.normalize injects RSA-specific fields', () => {
		const claims = rsaHandler.normalize('RS256', {});
		assert.strictEqual(claims.kty, 'RSA');
		assert.strictEqual(claims.e, 'AQAB');
		assert.ok('n' in claims);
		assert.ok(!('crv' in claims));
		assert.ok(!('x' in claims));
		assert.ok(!('k' in claims));
	});

	test('rsaHandler.validate accepts valid RSA claims and rejects bad exponent', () => {
		assert.deepStrictEqual(rsaHandler.validate({ kty: 'RSA', e: 'AQAB', n: VALID_RSA_N }), { valid: true });
		const bad = rsaHandler.validate({ kty: 'RSA', e: 'bad+/value' });
		assert.strictEqual(bad.valid, false);
		assert.ok((bad.error ?? '').includes('Exponent'));
	});

	test('ecHandler metadata is correct', () => {
		assert.strictEqual(ecHandler.kty, 'EC');
		assert.strictEqual(ecHandler.defaultAlgorithm, 'ES256');
	});

	test('ecHandler.normalize injects EC-specific fields', () => {
		const claims = ecHandler.normalize('ES256', { crv: 'P-256', x: 'abc_DEF', y: 'xyz_DEF' });
		assert.strictEqual(claims.kty, 'EC');
		assert.strictEqual(claims.crv, 'P-256');
		assert.strictEqual(claims.x, 'abc_DEF');
		assert.strictEqual(claims.y, 'xyz_DEF');
		assert.ok(!('e' in claims));
		assert.ok(!('n' in claims));
	});

	test('ecHandler.validate accepts valid EC claims and rejects bad coordinates', () => {
		assert.deepStrictEqual(ecHandler.validate({ kty: 'EC', x: 'abc_DEF-123', y: 'xyz_DEF-456' }), { valid: true });
		assert.strictEqual(ecHandler.validate({ kty: 'EC', x: 'bad+/value' }).valid, false);
		assert.strictEqual(ecHandler.validate({ kty: 'EC', y: 'bad+/value' }).valid, false);
	});

	test('okpHandler metadata is correct', () => {
		assert.strictEqual(okpHandler.kty, 'OKP');
		assert.strictEqual(okpHandler.defaultAlgorithm, 'EdDSA');
	});

	test('okpHandler.normalize injects OKP-specific fields', () => {
		const claims = okpHandler.normalize('EdDSA', { crv: 'Ed25519', x: 'abc_DEF' });
		assert.strictEqual(claims.kty, 'OKP');
		assert.strictEqual(claims.crv, 'Ed25519');
		assert.strictEqual(claims.x, 'abc_DEF');
		assert.ok(!('y' in claims));
		assert.ok(!('e' in claims));
	});

	test('okpHandler.validate accepts valid OKP claims and rejects bad public key', () => {
		assert.deepStrictEqual(okpHandler.validate({ kty: 'OKP', x: 'abc_DEF-123' }), { valid: true });
		assert.strictEqual(okpHandler.validate({ kty: 'OKP', x: 'bad+/value' }).valid, false);
	});

	test('octHandler metadata is correct', () => {
		assert.strictEqual(octHandler.kty, 'oct');
		assert.strictEqual(octHandler.defaultAlgorithm, 'HS256');
	});

	test('octHandler.normalize injects oct-specific fields', () => {
		const claims = octHandler.normalize('HS256', { k: 'abc_DEF-123' });
		assert.strictEqual(claims.kty, 'oct');
		assert.strictEqual(claims.k, 'abc_DEF-123');
		assert.ok(!('e' in claims));
		assert.ok(!('crv' in claims));
	});

	test('octHandler.validate accepts valid oct claims and rejects bad key value', () => {
		assert.deepStrictEqual(octHandler.validate({ kty: 'oct', k: 'abc_DEF-123' }), { valid: true });
		assert.strictEqual(octHandler.validate({ kty: 'oct', k: 'bad+/value' }).valid, false);
		assert.strictEqual(octHandler.validate({ kty: 'oct', k: '' }).valid, false);
	});

	test('normalizeManualClaims preserves the provided kty while omitting unsupported fields', () => {
		const claims = normalizeManualClaims('custom-alg', 'CUSTOM', { kty: 'CUSTOM', alg: 'custom-alg' });
		assert.strictEqual(claims.kty, 'CUSTOM');
		assert.ok(!('e' in claims));
		assert.ok(!('crv' in claims));
		assert.ok(!('k' in claims));
	});

	test('validateManualClaims rejects unsupported kty values', () => {
		assert.deepStrictEqual(validateManualClaims({ kty: 'CUSTOM', anything: 'goes' }), {
			valid: false,
			error: 'Key type (kty) must be one of RSA, EC, OKP, OCT.'
		});
	});
});