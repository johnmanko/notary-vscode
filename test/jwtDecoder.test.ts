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
import {
	base64UrlDecode,
	isValidJwtFormat,
	decodeJwt,
	isTokenExpired,
	isTokenNotYetValid,
	getTimestampClaims
} from '../src/utils/jwtDecoder';

suite('JWT Decoder Utils Test Suite', () => {
	
	suite('base64UrlDecode', () => {
		test('should decode standard Base64URL string', () => {
			// "hello" in Base64URL
			const result = base64UrlDecode('aGVsbG8');
			assert.strictEqual(result, 'hello');
		});
		
		test('should handle Base64URL with URL-safe characters', () => {
			// Test string with - and _ characters
			const result = base64UrlDecode('eyJ0eXAiOiJKV1QifQ');
			assert.strictEqual(result, '{"typ":"JWT"}');
		});
		
		test('should add padding when needed (2 chars)', () => {
			const result = base64UrlDecode('YQ');
			assert.strictEqual(result, 'a');
		});
		
		test('should add padding when needed (3 chars)', () => {
			const result = base64UrlDecode('YWI');
			assert.strictEqual(result, 'ab');
		});
		
		test('should handle UTF-8 encoded strings', () => {
			// Emoji encoded in Base64URL
			const result = base64UrlDecode('8J-YgA');
			assert.ok(result.length > 0);
		});
	});
	
	suite('isValidJwtFormat', () => {
		test('should return true for valid JWT format', () => {
			const token = 'header.payload.signature';
			assert.strictEqual(isValidJwtFormat(token), true);
		});
		
		test('should return false for JWT with only 2 parts', () => {
			const token = 'header.payload';
			assert.strictEqual(isValidJwtFormat(token), false);
		});
		
		test('should return false for JWT with 4 parts', () => {
			const token = 'header.payload.signature.extra';
			assert.strictEqual(isValidJwtFormat(token), false);
		});
		
		test('should return false for empty string', () => {
			assert.strictEqual(isValidJwtFormat(''), false);
		});
		
		test('should return false for whitespace only', () => {
			assert.strictEqual(isValidJwtFormat('   '), false);
		});
		
		test('should return false for null/undefined', () => {
			assert.strictEqual(isValidJwtFormat(null as any), false);
			assert.strictEqual(isValidJwtFormat(undefined as any), false);
		});
		
		test('should return false if any part is empty', () => {
			assert.strictEqual(isValidJwtFormat('.payload.signature'), false);
			assert.strictEqual(isValidJwtFormat('header..signature'), false);
			assert.strictEqual(isValidJwtFormat('header.payload.'), false);
		});
		
		test('should handle trimmed tokens', () => {
			const token = '  header.payload.signature  ';
			assert.strictEqual(isValidJwtFormat(token), true);
		});
	});
	
	suite('decodeJwt', () => {
		// Valid JWT token for testing (header: {"alg":"HS256","typ":"JWT"}, payload: {"sub":"1234567890","name":"John Doe","iat":1516239022})
		const validToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
		
		test('should successfully decode a valid JWT', () => {
			const result = decodeJwt(validToken);
			
			assert.strictEqual(result.success, true);
			if (result.success) {
				assert.ok(result.header);
				assert.ok(result.payload);
				assert.strictEqual(result.header.alg, 'HS256');
				assert.strictEqual(result.header.typ, 'JWT');
				assert.strictEqual(result.payload.sub, '1234567890');
				assert.strictEqual(result.payload.name, 'John Doe');
				assert.strictEqual(result.payload.iat, 1516239022);
			}
		});
		
		test('should return parts array', () => {
			const result = decodeJwt(validToken);
			
			assert.strictEqual(result.success, true);
			if (result.success) {
				assert.strictEqual(result.parts.length, 3);
				assert.strictEqual(result.parts[0], 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
				assert.strictEqual(result.parts[1], 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ');
			}
		});
		
		test('should fail for empty token', () => {
			const result = decodeJwt('');
			
			assert.strictEqual(result.success, false);
			if (!result.success) {
				assert.strictEqual(result.errorType, 'EMPTY_TOKEN');
				assert.ok(result.error.length > 0);
			}
		});
		
		test('should fail for token with wrong number of parts', () => {
			const result = decodeJwt('header.payload');
			
			assert.strictEqual(result.success, false);
			if (!result.success) {
				assert.strictEqual(result.errorType, 'INVALID_FORMAT');
				assert.ok(result.error.includes('expected 3'));
			}
		});
		
		test('should fail for invalid header encoding', () => {
			const result = decodeJwt('invalid!!!.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature');
			
			assert.strictEqual(result.success, false);
			if (!result.success) {
				assert.strictEqual(result.errorType, 'INVALID_HEADER');
			}
		});
		
		test('should fail for invalid payload encoding', () => {
			const result = decodeJwt('eyJhbGciOiJIUzI1NiJ9.invalid!!!.signature');
			
			assert.strictEqual(result.success, false);
			if (!result.success) {
				assert.strictEqual(result.errorType, 'INVALID_PAYLOAD');
			}
		});
		
		test('should fail for malformed JSON in header', () => {
			// "not-json" in Base64URL
			const result = decodeJwt('bm90LWpzb24.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature');
			
			assert.strictEqual(result.success, false);
			if (!result.success) {
				assert.strictEqual(result.errorType, 'INVALID_HEADER');
			}
		});
		
		test('should fail for malformed JSON in payload', () => {
			// "not-json" in Base64URL
			const result = decodeJwt('eyJhbGciOiJIUzI1NiJ9.bm90LWpzb24.signature');
			
			assert.strictEqual(result.success, false);
			if (!result.success) {
				assert.strictEqual(result.errorType, 'INVALID_PAYLOAD');
			}
		});
		
		test('should handle tokens with whitespace', () => {
			const result = decodeJwt(`  ${validToken}  `);
			
			assert.strictEqual(result.success, true);
		});
		
		test('should preserve signature as-is', () => {
			const result = decodeJwt(validToken);
			
			assert.strictEqual(result.success, true);
			if (result.success) {
				assert.strictEqual(result.signature, 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
			}
		});
	});
	
	suite('isTokenExpired', () => {
		test('should return true for expired token', () => {
			const payload = { exp: Math.floor(Date.now() / 1000) - 3600 }; // 1 hour ago
			assert.strictEqual(isTokenExpired(payload), true);
		});
		
		test('should return false for valid token', () => {
			const payload = { exp: Math.floor(Date.now() / 1000) + 3600 }; // 1 hour from now
			assert.strictEqual(isTokenExpired(payload), false);
		});
		
		test('should return false when no exp claim exists', () => {
			const payload = { sub: '1234567890' };
			assert.strictEqual(isTokenExpired(payload), false);
		});
		
		test('should return false when exp is not a number', () => {
			const payload = { exp: 'not-a-number' };
			assert.strictEqual(isTokenExpired(payload), false);
		});
		
		test('should handle edge case at exact expiration time', () => {
			const now = Math.floor(Date.now() / 1000);
			const payload = { exp: now };
			// Should be expired if exp <= now
			assert.strictEqual(isTokenExpired(payload), true);
		});
	});
	
	suite('isTokenNotYetValid', () => {
		test('should return true for not-yet-valid token', () => {
			const payload = { nbf: Math.floor(Date.now() / 1000) + 3600 }; // 1 hour from now
			assert.strictEqual(isTokenNotYetValid(payload), true);
		});
		
		test('should return false for valid token', () => {
			const payload = { nbf: Math.floor(Date.now() / 1000) - 3600 }; // 1 hour ago
			assert.strictEqual(isTokenNotYetValid(payload), false);
		});
		
		test('should return false when no nbf claim exists', () => {
			const payload = { sub: '1234567890' };
			assert.strictEqual(isTokenNotYetValid(payload), false);
		});
		
		test('should return false when nbf is not a number', () => {
			const payload = { nbf: 'not-a-number' };
			assert.strictEqual(isTokenNotYetValid(payload), false);
		});
	});
	
	suite('getTimestampClaims', () => {
		test('should extract all timestamp claims', () => {
			const payload = {
				iat: 1516239022,
				nbf: 1516239022,
				exp: 1516242622
			};
			
			const result = getTimestampClaims(payload);
			
			assert.strictEqual(result.iat, 1516239022);
			assert.strictEqual(result.nbf, 1516239022);
			assert.strictEqual(result.exp, 1516242622);
		});
		
		test('should handle missing timestamp claims', () => {
			const payload = { sub: '1234567890', name: 'John Doe' };
			
			const result = getTimestampClaims(payload);
			
			assert.strictEqual(result.iat, undefined);
			assert.strictEqual(result.nbf, undefined);
			assert.strictEqual(result.exp, undefined);
		});
		
		test('should only include valid number timestamps', () => {
			const payload = {
				iat: 1516239022,
				nbf: 'not-a-number',
				exp: 1516242622
			};
			
			const result = getTimestampClaims(payload);
			
			assert.strictEqual(result.iat, 1516239022);
			assert.strictEqual(result.nbf, undefined);
			assert.strictEqual(result.exp, 1516242622);
		});
		
		test('should handle partial timestamp claims', () => {
			const payload = { iat: 1516239022 };
			
			const result = getTimestampClaims(payload);
			
			assert.strictEqual(result.iat, 1516239022);
			assert.strictEqual(result.nbf, undefined);
			assert.strictEqual(result.exp, undefined);
		});
	});
});
