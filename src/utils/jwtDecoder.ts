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

/**
 * JWT Decoding utilities
 */

export interface JwtDecodeResult {
	success: true;
	header: Record<string, unknown>;
	payload: Record<string, unknown>;
	signature: string;
	parts: [string, string, string];
}

export interface JwtDecodeError {
	success: false;
	error: string;
	errorType: 'INVALID_FORMAT' | 'INVALID_HEADER' | 'INVALID_PAYLOAD' | 'EMPTY_TOKEN';
}

export type JwtResult = JwtDecodeResult | JwtDecodeError;

/**
 * Decodes a Base64URL-encoded string.
 * @param str - The Base64URL-encoded string
 * @returns The decoded string
 */
export function base64UrlDecode(str: string): string {
	// Replace URL-safe characters with standard Base64 characters
	let s = str.replaceAll('-', '+').replaceAll('_', '/');
	
	// Add padding if needed
	const pad = s.length % 4;
	if (pad === 2) {
		s += '==';
	} else if (pad === 3) {
		s += '=';
	}
	
	// Decode Base64
	const bytes = atob(s);
	
	// Try to decode as UTF-8
	try {
		return decodeURIComponent(
			bytes.split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join('')
		);
	} catch {
		// If UTF-8 decoding fails, return raw bytes
		return bytes;
	}
}

/**
 * Validates JWT format (3 parts separated by dots).
 * @param token - The JWT token string
 * @returns True if format is valid
 */
export function isValidJwtFormat(token: string): boolean {
	if (!token || typeof token !== 'string') {
		return false;
	}
	
	const trimmed = token.trim();
	if (!trimmed) {
		return false;
	}
	
	const parts = trimmed.split('.');
	return parts.length === 3 && parts.every(part => part.length > 0);
}

/**
 * Decodes and parses a JWT token.
 * @param token - The JWT token string
 * @returns A result object with decoded data or error information
 */
export function decodeJwt(token: string): JwtResult {
	const trimmed = token?.trim() ?? '';
	
	if (!trimmed) {
		return {
			success: false,
			error: 'Token is empty',
			errorType: 'EMPTY_TOKEN'
		};
	}
	
	const parts = trimmed.split('.');
	
	if (parts.length !== 3) {
		return {
			success: false,
			error: `Invalid JWT format — expected 3 dot-separated parts, got ${parts.length}`,
			errorType: 'INVALID_FORMAT'
		};
	}
	
	// Decode header
	let header: Record<string, unknown>;
	try {
		const headerStr = base64UrlDecode(parts[0]);
		header = JSON.parse(headerStr) as Record<string, unknown>;
	} catch (error) {
		return {
			success: false,
			error: 'Invalid JWT — header could not be decoded',
			errorType: 'INVALID_HEADER'
		};
	}
	
	// Decode payload
	let payload: Record<string, unknown>;
	try {
		const payloadStr = base64UrlDecode(parts[1]);
		payload = JSON.parse(payloadStr) as Record<string, unknown>;
	} catch (error) {
		return {
			success: false,
			error: 'Invalid JWT — payload could not be decoded',
			errorType: 'INVALID_PAYLOAD'
		};
	}
	
	return {
		success: true,
		header,
		payload,
		signature: parts[2],
		parts: [parts[0], parts[1], parts[2]]
	};
}

/**
 * Checks if a JWT token is expired based on the 'exp' claim.
 * @param payload - The decoded JWT payload
 * @returns True if expired, false otherwise (or if no exp claim exists)
 */
export function isTokenExpired(payload: Record<string, unknown>): boolean {
	if (typeof payload.exp !== 'number') {
		return false;
	}
	
	const now = Math.floor(Date.now() / 1000);
	return payload.exp <= now;
}

/**
 * Checks if a JWT token is not yet valid based on the 'nbf' (not before) claim.
 * @param payload - The decoded JWT payload
 * @returns True if not yet valid, false otherwise (or if no nbf claim exists)
 */
export function isTokenNotYetValid(payload: Record<string, unknown>): boolean {
	if (typeof payload.nbf !== 'number') {
		return false;
	}
	
	const now = Math.floor(Date.now() / 1000);
	return payload.nbf > now;
}

/**
 * Gets all timestamp claims from a JWT payload (iat, nbf, exp).
 * @param payload - The decoded JWT payload
 * @returns Object with timestamp claims that exist in the payload
 */
export function getTimestampClaims(payload: Record<string, unknown>): {
	iat?: number;
	nbf?: number;
	exp?: number;
} {
	const result: { iat?: number; nbf?: number; exp?: number } = {};
	
	if (typeof payload.iat === 'number') {
		result.iat = payload.iat;
	}
	if (typeof payload.nbf === 'number') {
		result.nbf = payload.nbf;
	}
	if (typeof payload.exp === 'number') {
		result.exp = payload.exp;
	}
	
	return result;
}
