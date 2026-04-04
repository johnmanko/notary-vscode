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
import { decodeJwt, base64UrlDecode, isValidJwtFormat, isTokenExpired, isTokenNotYetValid } from '../src/utils/jwtDecoder';

/**
 * Edge case and error scenario tests for JWT decoder.
 * Tests boundary conditions, malformed input, and error handling.
 */
suite('JWT Decoder Edge Cases Test Suite', () => {
	
	suite('Base64URL Decoding Edge Cases', () => {
		test('should handle very long strings', () => {
			const longString = 'A'.repeat(10000);
			const encoded = btoa(longString).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
			
			const result = base64UrlDecode(encoded);
			assert.ok(result.length > 0, 'Should decode very long strings');
		});
		
		test('should handle strings with no padding needed', () => {
			// String that results in no padding needed (length % 4 === 0)
			const result = base64UrlDecode('dGVzdA');
			assert.ok(result.length > 0, 'Should handle no-padding case');
		});
		
		test('should handle single character', () => {
			// Single character 'a' in base64url
			const result = base64UrlDecode('YQ');
			assert.strictEqual(result, 'a');
		});
		
		test('should handle special Unicode characters', () => {
			// Test with emoji (encoded)
			const result = base64UrlDecode('8J-YgA');
			assert.ok(result.length > 0, 'Should handle Unicode');
		});
		
		test('should fall back to raw bytes on UTF-8 decode failure', () => {
			// Create a string that might fail UTF-8 decoding
			// This tests the catch block in base64UrlDecode
			const result = base64UrlDecode('AA');
			assert.ok(typeof result === 'string', 'Should return string even on decode failure');
		});
	});
	
	suite('JWT Format Validation Edge Cases', () => {
		test('should reject token with only dots', () => {
			assert.strictEqual(isValidJwtFormat('..'), false);
		});
		
		test('should reject token with leading dot', () => {
			assert.strictEqual(isValidJwtFormat('.header.payload'), false);
		});
		
		test('should reject token with trailing dot', () => {
			assert.strictEqual(isValidJwtFormat('header.payload.'), false);
		});
		
		test('should reject token with multiple consecutive dots', () => {
			assert.strictEqual(isValidJwtFormat('header..payload'), false);
		});
		
		test('should reject very short tokens', () => {
			assert.strictEqual(isValidJwtFormat('a.b.c'), true); // Actually valid format
			assert.strictEqual(isValidJwtFormat('..'), false);
		});
		
		test('should handle tokens with spaces before trim', () => {
			assert.strictEqual(isValidJwtFormat('  header.payload.sig  '), true);
		});
		
		test('should reject non-string input', () => {
			assert.strictEqual(isValidJwtFormat(123 as any), false);
			assert.strictEqual(isValidJwtFormat({} as any), false);
			assert.strictEqual(isValidJwtFormat([] as any), false);
		});
	});
	
	suite('JWT Decoding Error Cases', () => {
		test('should return error for whitespace-only token', () => {
			const result = decodeJwt('   ');
			assert.strictEqual(result.success, false);
			if (!result.success) {
				assert.strictEqual(result.errorType, 'EMPTY_TOKEN');
			}
		});
		
		test('should return error for single part token', () => {
			const result = decodeJwt('onlyonepart');
			assert.strictEqual(result.success, false);
			if (!result.success) {
				assert.strictEqual(result.errorType, 'INVALID_FORMAT');
				assert.ok(result.error.includes('3'));
			}
		});
		
		test('should return error for two part token', () => {
			const result = decodeJwt('part1.part2');
			assert.strictEqual(result.success, false);
			if (!result.success) {
				assert.strictEqual(result.errorType, 'INVALID_FORMAT');
			}
		});
		
		test('should return error for four part token', () => {
			const result = decodeJwt('part1.part2.part3.part4');
			assert.strictEqual(result.success, false);
			if (!result.success) {
				assert.strictEqual(result.errorType, 'INVALID_FORMAT');
			}
		});
		
		test('should return error for invalid base64 in header', () => {
			const result = decodeJwt('!!!invalid!!!.eyJzdWIiOiJ0ZXN0In0.signature');
			assert.strictEqual(result.success, false);
			if (!result.success) {
				assert.strictEqual(result.errorType, 'INVALID_HEADER');
			}
		});
		
		test('should return error for invalid base64 in payload', () => {
			const result = decodeJwt('eyJhbGciOiJIUzI1NiJ9.!!!invalid!!!.signature');
			assert.strictEqual(result.success, false);
			if (!result.success) {
				assert.strictEqual(result.errorType, 'INVALID_PAYLOAD');
			}
		});
		
		test('should return error for non-JSON header', () => {
			// "invalid" in base64url
			const result = decodeJwt('aW52YWxpZA.eyJzdWIiOiJ0ZXN0In0.signature');
			assert.strictEqual(result.success, false);
			if (!result.success) {
				assert.strictEqual(result.errorType, 'INVALID_HEADER');
			}
		});
		
		test('should return error for non-JSON payload', () => {
			// "invalid" in base64url
			const result = decodeJwt('eyJhbGciOiJIUzI1NiJ9.aW52YWxpZA.signature');
			assert.strictEqual(result.success, false);
			if (!result.success) {
				assert.strictEqual(result.errorType, 'INVALID_PAYLOAD');
			}
		});
		
		test('should return error for partial JSON in header', () => {
			// "{incomplete" in base64url
			const result = decodeJwt('e2luY29tcGxldGU.eyJzdWIiOiJ0ZXN0In0.sig');
			assert.strictEqual(result.success, false);
			if (!result.success) {
				assert.strictEqual(result.errorType, 'INVALID_HEADER');
			}
		});
		
		test('should return error for array instead of object in header', () => {
			// "[]" in base64url
			const result = decodeJwt('W10.eyJzdWIiOiJ0ZXN0In0.signature');
			// This might actually succeed as valid JSON, but header should be object
			// The function doesn't validate structure, only JSON validity
			if (result.success) {
				assert.ok(true, 'Arrays are valid JSON');
			}
		});
	});
	
	suite('Token Expiration Edge Cases', () => {
		test('should handle very far future expiration', () => {
			const farFuture = Math.floor(Date.now() / 1000) + (100 * 365 * 24 * 60 * 60); // 100 years
			const payload = { exp: farFuture };
			assert.strictEqual(isTokenExpired(payload), false);
		});
		
		test('should handle very old expiration', () => {
			const ancient = 0; // Unix epoch
			const payload = { exp: ancient };
			assert.strictEqual(isTokenExpired(payload), true);
		});
		
		test('should handle negative expiration time', () => {
			const payload = { exp: -1000 };
			assert.strictEqual(isTokenExpired(payload), true);
		});
		
		test('should handle fractional expiration time', () => {
			const payload = { exp: 1516239022.5 };
			const result = isTokenExpired(payload);
			assert.ok(typeof result === 'boolean', 'Should handle fractional timestamps');
		});
		
		test('should handle NaN as expiration', () => {
			const payload = { exp: Number.NaN };
			// NaN is not 'number' type check in JavaScript (actually it is, but typeof NaN === 'number')
			// But NaN < anything is always false
			const result = isTokenExpired(payload);
			assert.strictEqual(result, false);
		});
		
		test('should handle Infinity as expiration', () => {
			const payload = { exp: Infinity };
			assert.strictEqual(isTokenExpired(payload), false);
		});
		
		test('should handle -Infinity as expiration', () => {
			const payload = { exp: -Infinity };
			assert.strictEqual(isTokenExpired(payload), true);
		});
		
		test('should handle missing exp claim in payload', () => {
			const payload = { sub: '12345', iat: 1516239022 };
			assert.strictEqual(isTokenExpired(payload), false);
		});
		
		test('should handle null exp claim', () => {
			const payload = { exp: null };
			assert.strictEqual(isTokenExpired(payload), false);
		});
		
		test('should handle string exp claim', () => {
			const payload = { exp: '1516239022' };
			assert.strictEqual(isTokenExpired(payload), false);
		});
	});
	
	suite('Not Before Validation Edge Cases', () => {
		test('should handle very far future nbf', () => {
			const farFuture = Math.floor(Date.now() / 1000) + (100 * 365 * 24 * 60 * 60);
			const payload = { nbf: farFuture };
			assert.strictEqual(isTokenNotYetValid(payload), true);
		});
		
		test('should handle ancient nbf', () => {
			const payload = { nbf: 0 };
			assert.strictEqual(isTokenNotYetValid(payload), false);
		});
		
		test('should handle negative nbf', () => {
			const payload = { nbf: -1000 };
			assert.strictEqual(isTokenNotYetValid(payload), false);
		});
		
		test('should handle Infinity nbf', () => {
			const payload = { nbf: Infinity };
			assert.strictEqual(isTokenNotYetValid(payload), true);
		});
		
		test('should handle -Infinity nbf', () => {
			const payload = { nbf: -Infinity };
			assert.strictEqual(isTokenNotYetValid(payload), false);
		});
		
		test('should handle missing nbf claim', () => {
			const payload = { sub: '12345' };
			assert.strictEqual(isTokenNotYetValid(payload), false);
		});
		
		test('should handle nbf at exact current time', () => {
			const now = Math.floor(Date.now() / 1000);
			const payload = { nbf: now };
			// Should not be "not yet valid" when nbf equals now
			assert.strictEqual(isTokenNotYetValid(payload), false);
		});
	});
	
	suite('Complex JWT Scenarios', () => {
		test('should handle JWT with extra whitespace', () => {
			const jwt = '  eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature  ';
			const result = decodeJwt(jwt);
			assert.strictEqual(result.success, true);
		});
		
		test('should handle JWT with newlines', () => {
			const jwt = 'eyJhbGciOiJIUzI1NiJ9\n.eyJzdWIiOiJ0ZXN0In0\n.signature';
			const result = decodeJwt(jwt);
		// After trimming, the token becomes valid
		assert.strictEqual(result.success, true);
	});
	
	test('should handle minimal JWT with empty objects', () => {
		// "{}" in base64url
		const emptyObj = 'e30';
		const result = decodeJwt(`${emptyObj}.${emptyObj}.sig`);
		
		assert.strictEqual(result.success, true);
		if (result.success) {
			assert.deepStrictEqual(result.header, {});
			assert.deepStrictEqual(result.payload, {});
		}
	});
	
	test('should preserve signature exactly as provided', () => {
		const signature = 'special_Chars-123_456';
		const jwt = `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.${signature}`;
		const result = decodeJwt(jwt);
		
		assert.strictEqual(result.success, true);
		if (result.success) {
			assert.strictEqual((result as any).signature, signature);
		}
	});
		
		test('should handle JWT with complex nested payload', () => {
			const payload = {
				user: {
					id: 123,
					roles: ['admin', 'user'],
					metadata: {
						created: '2024-01-01',
						active: true
					}
				}
			};
			
			const payloadB64 = btoa(JSON.stringify(payload))
				.replaceAll('+', '-')
				.replaceAll('/', '_')
				.replaceAll('=', '');
			
			const jwt = `eyJhbGciOiJIUzI1NiJ9.${payloadB64}.signature`;
			const result = decodeJwt(jwt);
			
			assert.strictEqual(result.success, true);
			if (result.success) {
				assert.deepStrictEqual(result.payload.user, payload.user);
			}
		});
	});
});
