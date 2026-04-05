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
import * as vscode from 'vscode';
import * as crypto from 'node:crypto';
import { ValidationKey, isURLKey, isJWKSJsonKey, needsRefresh, RefreshPeriod } from '../types/keyManagement';
import { KeyStorageManager } from './keyStorage';
import { fetchOIDCKeys } from './oidcKeyFetcher';

/**
 * Result of a key operation
 */
export interface KeyOperationResult {
	success: boolean;
	key?: ValidationKey;
	error?: string;
}

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
	selectionReason?: 'kid-match' | 'single-key' | 'override';
	availableKeyOptions: Array<{ ref: string; label: string }>;
}

function normalizePemInput(value: string): string {
	return value
		.trim()
		.replaceAll('\r\n', '\n')
		.replaceAll(String.raw`\n`, '\n');
}

function validateManualPemInput(value: string): { valid: boolean; normalized: string; error?: string } {
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

function parseStoredJson(decoded: string): Record<string, unknown> | null {
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

interface KeySetModel {
	keys: Record<string, unknown>[];
}

const RESERVED_KEYSET_FIELDS = new Set(['keys']);

function sanitizeJwkClaims(record: Record<string, unknown>): Record<string, unknown> {
	const sanitized = { ...record };
	for (const field of RESERVED_KEYSET_FIELDS) {
		delete sanitized[field];
	}
	return sanitized;
}

function parseKeySetModel(decoded: string): KeySetModel | null {
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

function getKeyRef(jwk: Record<string, unknown>, index: number): string {
	if (typeof jwk.kid === 'string' && jwk.kid.trim()) {
		return `kid:${jwk.kid.trim()}`;
	}
	return `index:${index}`;
}

function getKeyOptionLabel(jwk: Record<string, unknown>, index: number): string {
	const kid = typeof jwk.kid === 'string' && jwk.kid.trim() ? jwk.kid.trim() : '(none)';
	const kty = typeof jwk.kty === 'string' && jwk.kty.trim() ? jwk.kty.trim() : '(unknown)';
	const alg = typeof jwk.alg === 'string' && jwk.alg.trim() ? jwk.alg.trim() : '(unspecified)';
	return `keys[${index}] kty=${kty}, kid=${kid}, alg=${alg}`;
}

function getKeyOptions(keys: Record<string, unknown>[]): Array<{ ref: string; label: string }> {
	return keys.map((jwk, index) => ({
		ref: getKeyRef(jwk, index),
		label: getKeyOptionLabel(jwk, index)
	}));
}

function resolveKeyByKid(keys: Record<string, unknown>[], kid?: string): { key: Record<string, unknown>; index: number } | null {
	if (!kid) {
		return null;
	}
	const matchIndex = keys.findIndex(jwk => typeof jwk.kid === 'string' && jwk.kid === kid);
	if (matchIndex === -1) {
		return null;
	}
	return { key: keys[matchIndex], index: matchIndex };
}

function resolveKeyByRef(keys: Record<string, unknown>[], preferredRef?: string): { key: Record<string, unknown>; index: number } | null {
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

function normalizeManualClaims(
	algorithm: string,
	keyType: string,
	claims?: Record<string, unknown>
): Record<string, string> {
	const source = claims ?? {};
	return {
		kty: sanitizeClaim(source.kty, keyType),
		n: sanitizeClaim(source.n, ''),
		e: sanitizeClaim(source.e, 'AQAB'),
		use: sanitizeClaim(source.use, 'sig'),
		alg: sanitizeClaim(source.alg, algorithm),
		kid: sanitizeClaim(source.kid, 'key1'),
		typ: sanitizeClaim(source.typ, 'JWT')
	};
}

function validateManualClaims(claims: Record<string, string>): { valid: boolean; error?: string } {
	if (!claims.e) {
		return { valid: false, error: 'Exponent (e) is required and must be Base64URL encoded.' };
	}
	if (!isBase64Url(claims.e)) {
		return { valid: false, error: 'Exponent (e) must be Base64URL encoded (characters A-Z, a-z, 0-9, -, _).' };
	}
	if (claims.n && !isBase64Url(claims.n)) {
		return { valid: false, error: 'Modulus (n) must be Base64URL encoded when present.' };
	}
	return { valid: true };
}

function normalizeDescription(description?: string): { valid: boolean; value?: string; error?: string } {
	if (description === undefined) {
		return { valid: true, value: undefined };
	}
	const normalized = description.trim();
	if (normalized.length > 50) {
		return { valid: false, error: 'Description must be 50 characters or fewer.' };
	}
	return { valid: true, value: normalized };
}

function isJwkObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function selectBestJwk(keys: Record<string, unknown>[]): Record<string, unknown> | undefined {
	if (keys.length === 0) {
		return undefined;
	}
	const sigKey = keys.find(key => key.use === 'sig');
	return sigKey ?? keys[0];
}

function parseJWKSJsonInput(jwksJson: string): { success: boolean; selectedJwk?: Record<string, unknown>; jwkObjects?: Record<string, unknown>[]; normalizedJWKS?: string; error?: string } {
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

/**
 * Key Manager
 * Coordinates key storage, fetching, and refresh logic
 */
export class KeyManager {
	private readonly storageManager: KeyStorageManager;

	constructor(context: vscode.ExtensionContext) {
		this.storageManager = new KeyStorageManager(context);
	}

	/**
	 * Get all validation keys
	 */
	async getAllKeys(): Promise<ValidationKey[]> {
		return this.storageManager.getKeys();
	}

	/**
	 * Get a specific key by ID
	 */
	async getKeyById(id: string): Promise<ValidationKey | undefined> {
		return this.storageManager.getKeyById(id);
	}

	/**
	 * Add a new manual validation key
	 */
	async addManualKey(name: string, publicKey: string, algorithm: string = 'RS256', keyType: string = 'RSA', claims?: Record<string, unknown>, description?: string): Promise<KeyOperationResult> {
		try {
			// Validate input
			if (!name || name.trim().length === 0) {
				return { success: false, error: 'Key name is required' };
			}

			if (!publicKey || publicKey.trim().length === 0) {
				return { success: false, error: 'Public key is required' };
			}

			const descriptionResult = normalizeDescription(description);
			if (!descriptionResult.valid) {
				return { success: false, error: descriptionResult.error };
			}

			const pemValidation = validateManualPemInput(publicKey);
			if (!pemValidation.valid) {
				return { success: false, error: pemValidation.error || 'Invalid public key format' };
			}

			const normalizedAlgorithm = algorithm.trim() || 'RS256';
			const normalizedKeyType = keyType.trim().toUpperCase() || 'RSA';
			const normalizedClaims = normalizeManualClaims(normalizedAlgorithm, normalizedKeyType, claims);
			const claimsValidation = validateManualClaims(normalizedClaims);
			if (!claimsValidation.valid) {
				return { success: false, error: claimsValidation.error || 'Invalid manual key claims' };
			}
			const key = await this.storageManager.addManualKey(
				name.trim(),
				normalizedAlgorithm,
				normalizedKeyType,
				normalizedClaims,
				descriptionResult.value
			);
			return { success: true, key };

		} catch (error) {
			return {
				success: false,
				error: error instanceof Error ? error.message : 'Failed to add manual key'
			};
		}
	}

	/**
	 * Add a new URL-based validation key
	 * Fetches the key immediately from the provided URL
	 */
	async addURLKey(
		name: string,
		url: string,
		refreshPeriod: RefreshPeriod,
		description?: string
	): Promise<KeyOperationResult> {
		try {
			// Validate input
			if (!name || name.trim().length === 0) {
				return { success: false, error: 'Key name is required' };
			}

			if (!url || url.trim().length === 0) {
				return { success: false, error: 'URL is required' };
			}

			const descriptionResult = normalizeDescription(description);
			if (!descriptionResult.valid) {
				return { success: false, error: descriptionResult.error };
			}

			// Fetch the key from the URL
			const fetchResult = await fetchOIDCKeys(url.trim());
			if (!fetchResult.success || !fetchResult.jwks) {
				return {
					success: false,
					error: fetchResult.error || 'Failed to fetch key from URL'
				};
			}

			const jwkObjects = fetchResult.jwks.keys.filter(isJwkObject);
			if (jwkObjects.length === 0) {
				return { success: false, error: 'No suitable keys found in JWKS' };
			}
			// Store the key
			const key = await this.storageManager.addURLKey(
				name.trim(),
				url.trim(),
				refreshPeriod,
				jwkObjects,
				descriptionResult.value
			);

			return { success: true, key };

		} catch (error) {
			return {
				success: false,
				error: error instanceof Error ? error.message : 'Failed to add URL key'
			};
		}
	}

	/**
	 * Add a new direct JWKS JSON validation key
	 */
	async addJWKSJsonKey(name: string, jwksJson: string, description?: string): Promise<KeyOperationResult> {
		try {
			if (!name || name.trim().length === 0) {
				return { success: false, error: 'Key name is required' };
			}

			const descriptionResult = normalizeDescription(description);
			if (!descriptionResult.valid) {
				return { success: false, error: descriptionResult.error };
			}

			const parsedResult = parseJWKSJsonInput(jwksJson);
			if (!parsedResult.success || !parsedResult.selectedJwk || !parsedResult.normalizedJWKS) {
				return { success: false, error: parsedResult.error || 'Invalid JWKS JSON input' };
			}

			const jwkObjects = parsedResult.jwkObjects || [];
			if (jwkObjects.length === 0) {
				return { success: false, error: 'No suitable keys found in JWKS' };
			}
			const key = await this.storageManager.addJWKSJsonKey(
				name.trim(),
				parsedResult.normalizedJWKS,
				jwkObjects,
				descriptionResult.value
			);

			return { success: true, key };
		} catch (error) {
			return {
				success: false,
				error: error instanceof Error ? error.message : 'Failed to add JWKS JSON key'
			};
		}
	}

	async updateJWKSJsonKey(id: string, name: string, jwksJson: string, description?: string): Promise<{ success: boolean; error?: string }> {
		try {
			if (!name || name.trim().length === 0) {
				return { success: false, error: 'Key name is required' };
			}

			const descriptionResult = normalizeDescription(description);
			if (!descriptionResult.valid) {
				return { success: false, error: descriptionResult.error };
			}

			const key = await this.storageManager.getKeyById(id);
			if (!key) {
				return { success: false, error: 'Key not found' };
			}
			if (!isJWKSJsonKey(key)) {
				return { success: false, error: 'Cannot update JWKS JSON data for a non-JWKS key' };
			}

			const parsedResult = parseJWKSJsonInput(jwksJson);
			if (!parsedResult.success || !parsedResult.jwkObjects || !parsedResult.normalizedJWKS) {
				return { success: false, error: parsedResult.error || 'Invalid JWKS JSON input' };
			}

			const updated = await this.storageManager.updateJWKSJsonKey(
				id,
				name.trim(),
				parsedResult.normalizedJWKS,
				parsedResult.jwkObjects,
				descriptionResult.value
			);

			if (!updated) {
				return { success: false, error: 'Key not found or cannot be updated' };
			}

			return { success: true };
		} catch (error) {
			return {
				success: false,
				error: error instanceof Error ? error.message : 'Failed to update JWKS JSON key'
			};
		}
	}

	/**
	 * Force refresh a URL-based key
	 */
	async refreshURLKey(id: string): Promise<KeyOperationResult> {
		try {
			const key = await this.storageManager.getKeyById(id);
			
			if (!key) {
				return { success: false, error: 'Key not found' };
			}

			if (!isURLKey(key)) {
				return { success: false, error: 'Cannot refresh a manual key' };
			}

			// Fetch updated key
			const fetchResult = await fetchOIDCKeys(key.url);
			if (!fetchResult.success || !fetchResult.jwks) {
				return {
					success: false,
					error: fetchResult.error || 'Failed to fetch key from URL'
				};
			}

			const jwkObjects = fetchResult.jwks.keys.filter(isJwkObject);
			if (jwkObjects.length === 0) {
				return { success: false, error: 'No suitable keys found in JWKS' };
			}
			// Update the stored key
			const updatedKey = await this.storageManager.updateURLKey(id, jwkObjects);
			if (!updatedKey) {
				return { success: false, error: 'Failed to update key' };
			}

			return { success: true, key: updatedKey };

		} catch (error) {
			return {
				success: false,
				error: error instanceof Error ? error.message : 'Failed to refresh key'
			};
		}
	}

	/**
	 * Get a key and refresh it if needed
	 * This should be called before using a key for validation
	 */
	async getKeyAndRefreshIfNeeded(id: string): Promise<KeyOperationResult> {
		try {
			const key = await this.storageManager.getKeyById(id);
			
			if (!key) {
				return { success: false, error: 'Key not found' };
			}

			// If it's a manual key, just return it
			if (!isURLKey(key)) {
				return { success: true, key };
			}

			// Check if refresh is needed
			if (needsRefresh(key)) {
				// Attempt to refresh
				const refreshResult = await this.refreshURLKey(id);
				if (!refreshResult.success) {
					// Refresh failed, but return the old key with a warning
					return {
						success: true,
						key,
						error: `Warning: Key refresh failed (${refreshResult.error}). Using cached key.`
					};
				}
				return refreshResult;
			}

			// No refresh needed
			return { success: true, key };

		} catch (error) {
			return {
				success: false,
				error: error instanceof Error ? error.message : 'Failed to get key'
			};
		}
	}

	/**
	 * Delete a validation key
	 */
	async deleteKey(id: string): Promise<boolean> {
		return this.storageManager.deleteKey(id);
	}

	/**
	 * Update a manual validation key
	 */
	async updateManualKey(id: string, name: string, publicKey: string, algorithm: string = 'RS256', keyType: string = 'RSA', claims?: Record<string, unknown>, description?: string): Promise<{ success: boolean; error?: string }> {
		try {
			if (!name || name.trim().length === 0) {
				return { success: false, error: 'Key name is required' };
			}

			const descriptionResult = normalizeDescription(description);
			if (!descriptionResult.valid) {
				return { success: false, error: descriptionResult.error };
			}

			const pemValidation = validateManualPemInput(publicKey);
			if (!pemValidation.valid) {
				return { success: false, error: pemValidation.error || 'Invalid public key format' };
			}

			const normalizedAlgorithm = algorithm.trim() || 'RS256';
			const normalizedKeyType = keyType.trim().toUpperCase() || 'RSA';
			const normalizedClaims = normalizeManualClaims(normalizedAlgorithm, normalizedKeyType, claims);
			const claimsValidation = validateManualClaims(normalizedClaims);
			if (!claimsValidation.valid) {
				return { success: false, error: claimsValidation.error || 'Invalid manual key claims' };
			}
			const result = await this.storageManager.updateManualKey(
				id,
				name.trim(),
				normalizedAlgorithm,
				normalizedKeyType,
				normalizedClaims,
				descriptionResult.value
			);
			if (!result) {
				return { success: false, error: 'Key not found or cannot be updated' };
			}
			return { success: true };
		} catch (error) {
			return {
				success: false,
				error: error instanceof Error ? error.message : 'Failed to update key'
			};
		}
	}

	/**
	 * Update only the key name regardless of source type
	 */
	async updateKeyName(id: string, name: string, description?: string): Promise<{ success: boolean; error?: string }> {
		try {
			if (!name || name.trim().length === 0) {
				return { success: false, error: 'Key name is required' };
			}

			const descriptionResult = normalizeDescription(description);
			if (!descriptionResult.valid) {
				return { success: false, error: descriptionResult.error };
			}

			const result = await this.storageManager.updateKeyName(id, name.trim(), descriptionResult.value);
			if (!result) {
				return { success: false, error: 'Key not found or cannot be updated' };
			}

			return { success: true };
		} catch (error) {
			return {
				success: false,
				error: error instanceof Error ? error.message : 'Failed to update key name'
			};
		}
	}

	/**
	 * Update URL key editable settings (name + refresh period)
	 */
	async updateURLKeySettings(id: string, name: string, refreshPeriod: RefreshPeriod, description?: string): Promise<{ success: boolean; error?: string }> {
		try {
			if (!name || name.trim().length === 0) {
				return { success: false, error: 'Key name is required' };
			}

			const descriptionResult = normalizeDescription(description);
			if (!descriptionResult.valid) {
				return { success: false, error: descriptionResult.error };
			}

			const key = await this.storageManager.getKeyById(id);
			if (!key) {
				return { success: false, error: 'Key not found' };
			}
			if (!isURLKey(key)) {
				return { success: false, error: 'Cannot update URL settings for a manual key' };
			}

			const result = await this.storageManager.updateURLKeySettings(id, name.trim(), refreshPeriod, descriptionResult.value);
			if (!result) {
				return { success: false, error: 'Key not found or cannot be updated' };
			}

			return { success: true };
		} catch (error) {
			return {
				success: false,
				error: error instanceof Error ? error.message : 'Failed to update URL key settings'
			};
		}
	}

	/**
	 * Get the decoded public key data
	 */
	getDecodedKey(key: ValidationKey): string {
		return this.storageManager.getDecodedKey(key);
	}

	getValidationMaterial(key: ValidationKey, tokenKid?: string, selectedKeyRefOverride?: string): { success: boolean; data?: ValidationKeyMaterial; error?: string } {
		const decoded = this.getDecodedKey(key);
		const parsedModel = parseKeySetModel(decoded);

		if (!parsedModel || parsedModel.keys.length === 0) {
			return { success: false, error: 'No usable keys found in key set' };
		}

		const keyOptions = getKeyOptions(parsedModel.keys);
		const overrideMatch = resolveKeyByRef(parsedModel.keys, selectedKeyRefOverride);
		const kidMatch = resolveKeyByKid(parsedModel.keys, tokenKid);
		const singleKeyFallback = parsedModel.keys.length === 1 ? { key: parsedModel.keys[0], index: 0 } : null;
		const selected = overrideMatch || kidMatch || singleKeyFallback;
		const selectionReason: 'kid-match' | 'single-key' | 'override' = overrideMatch
			? 'override'
			: kidMatch
				? 'kid-match'
				: 'single-key';

		if (!selected) {
			return {
				success: false,
				error: tokenKid
					? `No key with kid "${tokenKid}" was found, and no fallback key is selected. Choose a fallback key in Key Details.`
					: 'JWT did not provide kid and no fallback key is selected. Choose a fallback key in Key Details.'
			};
		}

		try {
			const publicKey = crypto.createPublicKey({ key: selected.key as crypto.JsonWebKey, format: 'jwk' })
				.export({ type: 'spki', format: 'pem' })
				.toString();

			return {
				success: true,
				data: {
					publicKey,
					selectedKeyRef: getKeyRef(selected.key, selected.index),
					selectedKid: typeof selected.key.kid === 'string' ? selected.key.kid : undefined,
					algorithm: typeof selected.key.alg === 'string' ? selected.key.alg : undefined,
					typ: typeof selected.key.typ === 'string' ? selected.key.typ : undefined,
					selectionReason,
					availableKeyOptions: keyOptions
				}
			};
		} catch {
			const embeddedPem = selected.key.key;
			if (typeof embeddedPem === 'string') {
				return {
					success: true,
					data: {
						publicKey: embeddedPem,
						selectedKeyRef: getKeyRef(selected.key, selected.index),
						selectedKid: typeof selected.key.kid === 'string' ? selected.key.kid : undefined,
						algorithm: typeof selected.key.alg === 'string' ? selected.key.alg : undefined,
						typ: typeof selected.key.typ === 'string' ? selected.key.typ : undefined,
						selectionReason,
						availableKeyOptions: keyOptions
					}
				};
			}
			return { success: false, error: 'Selected key is not usable for validation' };
		}
	}

	getPublicKeyForValidation(key: ValidationKey): string {
		const material = this.getValidationMaterial(key);
		if (!material.success || !material.data) {
			return this.getDecodedKey(key);
		}
		return material.data.publicKey;
	}

	getKeyEditorData(key: ValidationKey): KeyEditorData {
		const decoded = this.getDecodedKey(key);
		const parsedModel = parseKeySetModel(decoded);

		if (!parsedModel || parsedModel.keys.length === 0) {
			return {
				claims: {},
				decodedKey: decoded,
				rawJson: isURLKey(key)
					? decoded
					: isJWKSJsonKey(key)
						? key.rawJwksJson
						: undefined
			};
		}

		const keyOptions = getKeyOptions(parsedModel.keys);
		const selectedIndex = parsedModel.keys.findIndex(candidate => candidate.use === 'sig');
		const selectedJwk = selectedIndex >= 0 ? parsedModel.keys[selectedIndex] : parsedModel.keys[0];

		let decodedKey = '';
		if (selectedJwk) {
			try {
				decodedKey = crypto.createPublicKey({ key: selectedJwk as crypto.JsonWebKey, format: 'jwk' })
					.export({ type: 'spki', format: 'pem' })
					.toString();
			} catch {
				decodedKey = '';
			}
		}

		return {
			claims: selectedJwk,
			rawJson: isURLKey(key)
				? JSON.stringify({ keys: parsedModel.keys })
				: isJWKSJsonKey(key)
					? key.rawJwksJson
					: undefined,
			decodedKey,
			algorithm: typeof selectedJwk.alg === 'string' ? selectedJwk.alg : undefined,
			typ: typeof selectedJwk.typ === 'string' ? selectedJwk.typ : undefined,
			kid: typeof selectedJwk.kid === 'string' ? selectedJwk.kid : undefined,
			availableKeyOptions: keyOptions
		};
	}

	/**
	 * Check all URL keys and refresh any that need it
	 * Can be called periodically or on extension activation
	 */
	async refreshAllExpiredKeys(): Promise<void> {
		const keys = await this.getAllKeys();
		const urlKeys = keys.filter(isURLKey);
		const expiredKeys = urlKeys.filter(needsRefresh);

		// Refresh all expired keys in parallel
		await Promise.allSettled(
			expiredKeys.map(key => this.refreshURLKey(key.id))
		);
	}
}
