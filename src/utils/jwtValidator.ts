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
import { decodeJwt } from './jwtDecoder';

/**
 * Result of JWT signature validation
 */
export interface ValidationResult {
	valid: boolean;
	message: string;
	details?: {
		algorithm?: string;
		keyType?: string;
		error?: string;
	};
}

export interface ManualKeyValidationMetadata {
	algorithm: string;
	typ: string;
	kid?: string;
}

/**
 * Parse JWK (JSON Web Key) from stored key data
 */
function parsePublicKey(keyData: string): { type: string; key: string | object } {
	const normalizedKeyData = keyData
		.trim()
		.replaceAll('\r\n', '\n')
		.replaceAll(String.raw`\n`, '\n');

	try {
		// Try to parse as JSON (JWK format)
		const jwk = JSON.parse(normalizedKeyData);
		if (jwk.kty) {
			return { type: 'jwk', key: jwk };
		}
	} catch {
		// Not JSON, assume PEM format
		if (normalizedKeyData.includes('BEGIN PUBLIC KEY') || normalizedKeyData.includes('BEGIN RSA PUBLIC KEY')) {
			return { type: 'pem', key: normalizedKeyData };
		}
	}
	
	return { type: 'unknown', key: normalizedKeyData };
}

function headerValueToString(value: unknown): string {
	if (typeof value === 'string') {
		return value;
	}
	return '[non-string value]';
}

function validateHeaderAgainstMetadata(
	header: Record<string, unknown>,
	algorithm: string,
	metadata?: ManualKeyValidationMetadata
): ValidationResult | null {
	if (!metadata) {
		return null;
	}

	if (algorithm !== metadata.algorithm) {
		return {
			valid: false,
			message: `JWT algorithm mismatch. Expected ${metadata.algorithm}, got ${algorithm}`,
			details: {
				algorithm
			}
		};
	}

	if (header.typ && header.typ !== metadata.typ) {
		return {
			valid: false,
			message: `JWT type mismatch. Expected ${metadata.typ}, got ${headerValueToString(header.typ)}`,
			details: {
				algorithm
			}
		};
	}

	if (metadata.kid && header.kid && header.kid !== metadata.kid) {
		return {
			valid: false,
			message: `JWT key id mismatch. Expected ${metadata.kid}, got ${headerValueToString(header.kid)}`,
			details: {
				algorithm
			}
		};
	}

	return null;
}

async function validateParsedKey(
	token: string,
	parsedKey: { type: string; key: string | object },
	algorithm: string
): Promise<ValidationResult> {
	if (parsedKey.type !== 'jwk' && parsedKey.type !== 'pem') {
		return {
			valid: false,
			message: 'Unknown key format. Expected PEM or JWK format.',
			details: {
				algorithm,
				keyType: parsedKey.type
			}
		};
	}

	try {
		const jose = await import('jose');
		const verificationKey = parsedKey.type === 'jwk'
			? await jose.importJWK(parsedKey.key as Record<string, unknown>, algorithm)
			: await jose.importSPKI(parsedKey.key as string, algorithm);

		await jose.compactVerify(token, verificationKey, {
			algorithms: [algorithm]
		});

		return {
			valid: true,
			message: 'JWT signature verified successfully.',
			details: {
				algorithm,
				keyType: parsedKey.type.toUpperCase()
			}
		};
	} catch (error) {
		return {
			valid: false,
			message: `JWT signature verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
			details: {
				algorithm,
				keyType: parsedKey.type.toUpperCase(),
				error: error instanceof Error ? error.message : 'Unknown error'
			}
		};
	}
}

/**
 * Validate JWT signature using a public key
 * 
 * NOTE: This is a basic implementation that demonstrates the validation flow.
 * For production use, consider using a dedicated JWT library like 'jsonwebtoken' or 'jose'
 * which provides comprehensive support for all JWT algorithms and proper key handling.
 */
export async function validateJWTSignature(token: string, publicKeyData: string, metadata?: ManualKeyValidationMetadata): Promise<ValidationResult> {
	try {
		// First, decode the token to get header and payload
		const decoded = decodeJwt(token);
		if (!decoded.success) {
			return {
				valid: false,
				message: `Invalid JWT format: ${decoded.error}`
			};
		}

		const { header, parts } = decoded;
		
		// Verify we have all three parts
		if (parts.length !== 3) {
			return {
				valid: false,
				message: 'JWT must have exactly 3 parts (header.payload.signature)'
			};
		}

		const algorithm = header.alg as string;
		if (!algorithm) {
			return {
				valid: false,
				message: 'JWT header missing "alg" field'
			};
		}

		const metadataValidation = validateHeaderAgainstMetadata(header, algorithm, metadata);
		if (metadataValidation) {
			return metadataValidation;
		}

		// Parse the public key
		const parsedKey = parsePublicKey(publicKeyData);

		return await validateParsedKey(token, parsedKey, algorithm);

	} catch (error) {
		return {
			valid: false,
			message: `Validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
			details: {
				error: error instanceof Error ? error.message : 'Unknown error'
			}
		};
	}
}

/**
 * Basic structural validation of a JWT (without cryptographic signature verification)
 */
export function validateJWTStructure(token: string): ValidationResult {
	const decoded = decodeJwt(token);
	
	if (!decoded.success) {
		return {
			valid: false,
			message: `Invalid JWT structure: ${decoded.error}`
		};
	}

	const { header } = decoded;

	// Check for required fields
	if (!header.alg) {
		return {
			valid: false,
			message: 'JWT header missing required "alg" field'
		};
	}

	if (!header.typ || header.typ !== 'JWT') {
		return {
			valid: false,
			message: 'JWT header "typ" should be "JWT"',
			details: {
				algorithm: header.alg as string
			}
		};
	}

	return {
		valid: true,
		message: 'JWT structure is valid (signature not verified)',
		details: {
			algorithm: header.alg as string
		}
	};
}
