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
import * as crypto from 'node:crypto';
import { isJWKSJsonKey, isURLKey, ValidationKey } from '../types/keyManagement';

export type KeySelectionReason = 'kid-match' | 'single-key' | 'override';

export interface KeyEditorData {
	claims: Record<string, unknown>;
	rawJson?: string;
	decodedKey: string;
	algorithm?: string;
	typ?: string;
	kid?: string;
	availableKeyOptions?: Array<{ ref: string; label: string }>;
}

export interface ValidationKeyMaterial {
	publicKey: string;
	selectedKeyRef: string;
	selectedKid?: string;
	algorithm?: string;
	typ?: string;
	selectionReason?: KeySelectionReason;
	availableKeyOptions: Array<{ ref: string; label: string }>;
}

export interface KeySetModel {
	keys: Record<string, unknown>[];
}

export interface JWKSJsonParseResult {
	success: boolean;
	selectedJwk?: Record<string, unknown>;
	jwkObjects?: Record<string, unknown>[];
	normalizedJWKS?: string;
	error?: string;
}

const RESERVED_KEYSET_FIELDS = new Set(['keys']);

function sanitizeClaim(value: unknown, fallback: string): string {
	if (typeof value !== 'string') {
		return fallback;
	}
	const trimmed = value.trim();
	return trimmed || fallback;
}

function isBase64Url(value: string): boolean {
	return /^[A-Za-z0-9_-]+$/.test(value);
}

function validateRequiredBase64UrlClaim(claims: Record<string, string>, field: string, label: string): { valid: boolean; error?: string } {
	const value = claims[field];
	if (!value) {
		return { valid: false, error: `${label} is required and must be Base64URL encoded.` };
	}
	if (!isBase64Url(value)) {
		return { valid: false, error: `${label} must be Base64URL encoded (characters A-Z, a-z, 0-9, -, _).` };
	}
	return { valid: true };
}

function validateOptionalBase64UrlClaim(claims: Record<string, string>, field: string, label: string): { valid: boolean; error?: string } {
	const value = claims[field];
	if (!value) {
		return { valid: true };
	}
	if (!isBase64Url(value)) {
		return { valid: false, error: `${label} must be Base64URL encoded when present.` };
	}
	return { valid: true };
}

function normalizeCommonManualClaims(algorithm: string, keyType: string, claims?: Record<string, unknown>): Record<string, string> {
	const source = claims ?? {};
	const normalized: Record<string, string> = {};

	normalized.kty = sanitizeClaim(source.kty, keyType);
	normalized.use = sanitizeClaim(source.use, 'sig');
	normalized.alg = sanitizeClaim(source.alg, algorithm);
	normalized.kid = sanitizeClaim(source.kid, 'key1');
	normalized.typ = sanitizeClaim(source.typ, 'JWT');

	return normalized;
}

/**
 * A KtyHandler bundles all kty-specific logic (field normalization and claim validation)
 * into a single named object per key type.  Exporting them individually makes it easy to
 * add support for new key types without touching the dispatch registry, and makes each
 * handler directly testable in isolation.
 */
export interface KtyHandler {
	readonly kty: string;
	readonly defaultAlgorithm: string;
	normalize(algorithm: string, claims?: Record<string, unknown>): Record<string, string>;
	validate(claims: Record<string, string>): { valid: boolean; error?: string };
}

export const rsaHandler: KtyHandler = {
	kty: 'RSA',
	defaultAlgorithm: 'RS256',
	normalize(algorithm, claims) {
		const normalized = normalizeCommonManualClaims(algorithm, 'RSA', claims);
		normalized.n = sanitizeClaim(claims?.n, '');
		normalized.e = sanitizeClaim(claims?.e, 'AQAB');
		return normalized;
	},
	validate(claims) {
		const exponentValidation = validateRequiredBase64UrlClaim(claims, 'e', 'Exponent (e)');
		if (!exponentValidation.valid) {
			return exponentValidation;
		}
		return validateOptionalBase64UrlClaim(claims, 'n', 'Modulus (n)');
	}
};

export const ecHandler: KtyHandler = {
	kty: 'EC',
	defaultAlgorithm: 'ES256',
	normalize(algorithm, claims) {
		const normalized = normalizeCommonManualClaims(algorithm, 'EC', claims);
		normalized.crv = sanitizeClaim(claims?.crv, '');
		normalized.x = sanitizeClaim(claims?.x, '');
		normalized.y = sanitizeClaim(claims?.y, '');
		return normalized;
	},
	validate(claims) {
		if (!claims.crv?.trim()) {
			return { valid: false, error: 'Curve (crv) is required for EC keys.' };
		}
		const xValidation = validateOptionalBase64UrlClaim(claims, 'x', 'X coordinate (x)');
		if (!xValidation.valid) {
			return xValidation;
		}
		return validateOptionalBase64UrlClaim(claims, 'y', 'Y coordinate (y)');
	}
};

export const okpHandler: KtyHandler = {
	kty: 'OKP',
	defaultAlgorithm: 'EdDSA',
	normalize(algorithm, claims) {
		const normalized = normalizeCommonManualClaims(algorithm, 'OKP', claims);
		normalized.crv = sanitizeClaim(claims?.crv, '');
		normalized.x = sanitizeClaim(claims?.x, '');
		return normalized;
	},
	validate(claims) {
		if (!claims.crv?.trim()) {
			return { valid: false, error: 'Curve (crv) is required for OKP keys.' };
		}
		return validateOptionalBase64UrlClaim(claims, 'x', 'Public key (x)');
	}
};

export const octHandler: KtyHandler = {
	kty: 'oct',
	defaultAlgorithm: 'HS256',
	normalize(algorithm, claims) {
		const normalized = normalizeCommonManualClaims(algorithm, 'oct', claims);
		normalized.k = sanitizeClaim(claims?.k, '');
		return normalized;
	},
	validate(claims) {
		return validateRequiredBase64UrlClaim(claims, 'k', 'Key value (k)');
	}
};

export const SUPPORTED_MANUAL_KTY_OPTIONS = ['RSA', 'EC', 'OKP', 'OCT'] as const;

const ktyHandlers: Record<string, KtyHandler> = {
	RSA: rsaHandler,
	EC: ecHandler,
	OKP: okpHandler,
	OCT: octHandler
};

export function isSupportedManualKty(keyType: string): boolean {
	return keyType.toUpperCase() in ktyHandlers;
}

function getKtyHandler(keyType: string): KtyHandler | undefined {
	return ktyHandlers[keyType.toUpperCase()];
}

function sanitizeJwkClaims(record: Record<string, unknown>): Record<string, unknown> {
	const sanitized = { ...record };
	for (const field of RESERVED_KEYSET_FIELDS) {
		delete sanitized[field];
	}
	return sanitized;
}

function exportPublicKeyFromJwk(jwk: Record<string, unknown>): string {
	return crypto.createPublicKey({ key: jwk as crypto.JsonWebKey, format: 'jwk' })
		.export({ type: 'spki', format: 'pem' })
		.toString();
}

function getSelectionReason(overrideMatch: unknown, kidMatch: unknown): KeySelectionReason {
	if (overrideMatch) {
		return 'override';
	}
	if (kidMatch) {
		return 'kid-match';
	}
	return 'single-key';
}

function getMissingSelectionError(tokenKid?: string): string {
	return tokenKid
		? `No key with kid "${tokenKid}" was found, and no fallback key is selected. Choose a fallback key in Key Details.`
		: 'JWT did not provide kid and no fallback key is selected. Choose a fallback key in Key Details.';
}

function buildValidationMaterial(
	selected: { key: Record<string, unknown>; index: number },
	publicKey: string,
	selectionReason: KeySelectionReason,
	availableKeyOptions: Array<{ ref: string; label: string }>
): ValidationKeyMaterial {
	return {
		publicKey,
		selectedKeyRef: getKeyRef(selected.key, selected.index),
		selectedKid: typeof selected.key.kid === 'string' ? selected.key.kid : undefined,
		algorithm: typeof selected.key.alg === 'string' ? selected.key.alg : undefined,
		typ: typeof selected.key.typ === 'string' ? selected.key.typ : undefined,
		selectionReason,
		availableKeyOptions
	};
}

function getEditorRawJson(key: ValidationKey, parsedKeys: Record<string, unknown>[], decoded: string): string | undefined {
	if (isURLKey(key)) {
		return parsedKeys.length > 0 ? JSON.stringify({ keys: parsedKeys }) : decoded;
	}
	if (isJWKSJsonKey(key)) {
		return key.rawJwksJson;
	}
	return undefined;
}

function getDecodedKeyFromJwk(selectedJwk: Record<string, unknown> | undefined): string {
	if (!selectedJwk) {
		return '';
	}
	try {
		return exportPublicKeyFromJwk(selectedJwk);
	} catch {
		return '';
	}
}

export function normalizePemInput(value: string): string {
	return value
		.trim()
		.replaceAll('\r\n', '\n')
		.replaceAll(String.raw`\n`, '\n');
}

export function validateManualPemInput(value: string): { valid: boolean; normalized: string; error?: string } {
	const normalized = normalizePemInput(value);

	if (!normalized) {
		return { valid: false, normalized, error: 'Public key is required' };
	}

	const supportedHeaders = [
		{ begin: '-----BEGIN PUBLIC KEY-----', end: '-----END PUBLIC KEY-----' },
		{ begin: '-----BEGIN RSA PUBLIC KEY-----', end: '-----END RSA PUBLIC KEY-----' },
		{ begin: '-----BEGIN EC PUBLIC KEY-----', end: '-----END EC PUBLIC KEY-----' }
	];

	const headerMatch = supportedHeaders.find(h => normalized.includes(h.begin) && normalized.includes(h.end));
	if (!headerMatch) {
		return {
			valid: false,
			normalized,
			error: 'Invalid PEM format. Expected BEGIN/END PUBLIC KEY block.'
		};
	}

	const beginIndex = normalized.indexOf(headerMatch.begin) + headerMatch.begin.length;
	const endIndex = normalized.indexOf(headerMatch.end);
	const base64Body = normalized.slice(beginIndex, endIndex).replaceAll('\n', '').trim();

	if (!base64Body || !/^[A-Za-z0-9+/=]+$/.test(base64Body)) {
		return {
			valid: false,
			normalized,
			error: 'Invalid PEM body. Only base64 key content is allowed between headers.'
		};
	}

	return { valid: true, normalized };
}

export function parseStoredJson(decoded: string): Record<string, unknown> | null {
	try {
		const parsed = JSON.parse(decoded);
		if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
			return parsed as Record<string, unknown>;
		}
		return null;
	} catch {
		return null;
	}
}

export function isJwkObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function parseKeySetModel(decoded: string): KeySetModel | null {
	const parsed = parseStoredJson(decoded);
	if (!parsed) {
		return null;
	}

	if (Array.isArray(parsed.keys)) {
		return {
			keys: parsed.keys.filter(isJwkObject).map(sanitizeJwkClaims)
		};
	}

	return {
		keys: [sanitizeJwkClaims(parsed)]
	};
}

export function getKeyRef(jwk: Record<string, unknown>, index: number): string {
	if (typeof jwk.kid === 'string' && jwk.kid.trim()) {
		return `kid:${jwk.kid.trim()}`;
	}
	return `index:${index}`;
}

export function getKeyOptionLabel(jwk: Record<string, unknown>, index: number): string {
	const kid = typeof jwk.kid === 'string' && jwk.kid.trim() ? jwk.kid.trim() : '(none)';
	const kty = typeof jwk.kty === 'string' && jwk.kty.trim() ? jwk.kty.trim() : '(unknown)';
	const alg = typeof jwk.alg === 'string' && jwk.alg.trim() ? jwk.alg.trim() : '(unspecified)';
	return `keys[${index}] kty=${kty}, kid=${kid}, alg=${alg}`;
}

export function getKeyOptions(keys: Record<string, unknown>[]): Array<{ ref: string; label: string }> {
	return keys.map((jwk, index) => ({
		ref: getKeyRef(jwk, index),
		label: getKeyOptionLabel(jwk, index)
	}));
}

export function resolveKeyByKid(keys: Record<string, unknown>[], kid?: string): { key: Record<string, unknown>; index: number } | null {
	if (!kid) {
		return null;
	}
	const matchIndex = keys.findIndex(jwk => typeof jwk.kid === 'string' && jwk.kid === kid);
	if (matchIndex === -1) {
		return null;
	}
	return { key: keys[matchIndex], index: matchIndex };
}

export function resolveKeyByRef(keys: Record<string, unknown>[], preferredRef?: string): { key: Record<string, unknown>; index: number } | null {
	if (!preferredRef) {
		return null;
	}
	if (preferredRef.startsWith('kid:')) {
		return resolveKeyByKid(keys, preferredRef.slice(4));
	}
	if (preferredRef.startsWith('index:')) {
		const index = Number.parseInt(preferredRef.slice(6), 10);
		if (!Number.isNaN(index) && index >= 0 && index < keys.length) {
			return { key: keys[index], index };
		}
	}
	return null;
}

export function normalizeManualClaims(algorithm: string, keyType: string, claims?: Record<string, unknown>): Record<string, string> {
	const normalizedKeyType = keyType.trim().toUpperCase() || 'RSA';
	const handler = getKtyHandler(normalizedKeyType);
	return handler
		? handler.normalize(algorithm, claims)
		: normalizeCommonManualClaims(algorithm, normalizedKeyType, claims);
}

export function validateManualClaims(claims: Record<string, string>): { valid: boolean; error?: string } {
	const normalizedKeyType = sanitizeClaim(claims.kty, '').toUpperCase();
	const handler = getKtyHandler(normalizedKeyType);
	if (!handler) {
		return {
			valid: false,
			error: `Key type (kty) must be one of ${SUPPORTED_MANUAL_KTY_OPTIONS.join(', ')}.`
		};
	}
	return handler.validate(claims);
}

export function normalizeDescription(description?: string): { valid: boolean; value?: string; error?: string } {
	if (description === undefined) {
		return { valid: true, value: undefined };
	}
	const normalized = description.trim();
	if (normalized.length > 50) {
		return { valid: false, error: 'Description must be 50 characters or fewer.' };
	}
	return { valid: true, value: normalized };
}

export function getErrorMessage(error: unknown, fallback: string): string {
	return error instanceof Error ? error.message : fallback;
}

export function selectBestJwk(keys: Record<string, unknown>[]): Record<string, unknown> | undefined {
	if (keys.length === 0) {
		return undefined;
	}
	const sigKey = keys.find(key => key.use === 'sig');
	return sigKey ?? keys[0];
}

/**
 * Builds a canonical JWKS JSON string from an array of JWK objects.
 * Use this before calling parseJWKSJsonInput to validate any assembled key set,
 * regardless of how it was produced (fetch, manual, or direct JSON input).
 */
export function buildJwksJson(keys: Record<string, unknown>[]): string {
	return JSON.stringify({ keys });
}

export function parseJWKSJsonInput(jwksJson: string): JWKSJsonParseResult {
	const trimmed = jwksJson.trim();
	if (!trimmed) {
		return { success: false, error: 'JWKS JSON is required' };
	}

	try {
		const parsed = JSON.parse(trimmed);
		if (!isJwkObject(parsed)) {
			return { success: false, error: 'Invalid JWKS format: root must be a JSON object' };
		}
		const keysValue = parsed.keys;
		if (!Array.isArray(keysValue)) {
			return { success: false, error: 'Invalid JWKS format: missing keys array' };
		}
		const jwkObjects = keysValue.filter(isJwkObject);
		const selected = selectBestJwk(jwkObjects);
		if (!selected) {
			return { success: false, error: 'No suitable keys found in JWKS' };
		}
		return {
			success: true,
			selectedJwk: selected,
			jwkObjects,
			normalizedJWKS: JSON.stringify(parsed)
		};
	} catch {
		return { success: false, error: 'Invalid JSON format for JWKS input' };
	}
}

export function getValidationMaterialFromDecoded(
	decoded: string,
	tokenKid?: string,
	selectedKeyRefOverride?: string
): { success: boolean; data?: ValidationKeyMaterial; error?: string } {
	const parsedModel = parseKeySetModel(decoded);

	if (!parsedModel || parsedModel.keys.length === 0) {
		return { success: false, error: 'No usable keys found in key set' };
	}

	const keyOptions = getKeyOptions(parsedModel.keys);
	const overrideMatch = resolveKeyByRef(parsedModel.keys, selectedKeyRefOverride);
	const kidMatch = resolveKeyByKid(parsedModel.keys, tokenKid);
	const singleKeyFallback = parsedModel.keys.length === 1 ? { key: parsedModel.keys[0], index: 0 } : null;
	const selected = overrideMatch || kidMatch || singleKeyFallback;
	const selectionReason = getSelectionReason(overrideMatch, kidMatch);

	if (!selected) {
		return { success: false, error: getMissingSelectionError(tokenKid) };
	}

	try {
		const publicKey = exportPublicKeyFromJwk(selected.key);
		return { success: true, data: buildValidationMaterial(selected, publicKey, selectionReason, keyOptions) };
	} catch {
		const selectedKty = typeof selected.key.kty === 'string' ? selected.key.kty.trim().toLowerCase() : '';
		if (selectedKty === 'oct') {
			return {
				success: true,
				data: buildValidationMaterial(selected, JSON.stringify(selected.key), selectionReason, keyOptions)
			};
		}
		const embeddedPem = selected.key.key;
		if (typeof embeddedPem === 'string') {
			return { success: true, data: buildValidationMaterial(selected, embeddedPem, selectionReason, keyOptions) };
		}
		return { success: false, error: 'Selected key is not usable for validation' };
	}
}

export function buildKeyEditorData(key: ValidationKey, decoded: string): KeyEditorData {
	const parsedModel = parseKeySetModel(decoded);

	if (!parsedModel || parsedModel.keys.length === 0) {
		return {
			claims: {},
			decodedKey: decoded,
			rawJson: getEditorRawJson(key, [], decoded)
		};
	}

	const keyOptions = getKeyOptions(parsedModel.keys);
	const selectedIndex = parsedModel.keys.findIndex(candidate => candidate.use === 'sig');
	const selectedJwk = selectedIndex >= 0 ? parsedModel.keys[selectedIndex] : parsedModel.keys[0];

	return {
		claims: selectedJwk,
		rawJson: getEditorRawJson(key, parsedModel.keys, decoded),
		decodedKey: getDecodedKeyFromJwk(selectedJwk),
		algorithm: typeof selectedJwk.alg === 'string' ? selectedJwk.alg : undefined,
		typ: typeof selectedJwk.typ === 'string' ? selectedJwk.typ : undefined,
		kid: typeof selectedJwk.kid === 'string' ? selectedJwk.kid : undefined,
		availableKeyOptions: keyOptions
	};
}