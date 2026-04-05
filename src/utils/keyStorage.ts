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
import { ValidationKey, URLValidationKey, ManualValidationKey, JWKSJsonValidationKey, KeySource, RefreshPeriod, calculateNextRefresh } from '../types/keyManagement';

const STORAGE_KEY = 'notary.validationKeys';

/**
 * Encode a string to base64
 */
export function encodeToBase64(data: string): string {
	return Buffer.from(data, 'utf8').toString('base64');
}

/**
 * Decode a base64 string
 */
export function decodeFromBase64(data: string): string {
	return Buffer.from(data, 'base64').toString('utf8');
}

/**
 * Generate a unique ID for a key
 */
function generateKeyId(): string {
	return `key_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
}

/**
 * Normalize PEM text entered in text areas.
 * Supports both real newlines and escaped "\\n" sequences.
 */
function normalizePemInput(publicKey: string): string {
	return publicKey
		.trim()
		.replaceAll('\r\n', '\n')
		.replaceAll(String.raw`\n`, '\n');
}

function sanitizeClaimValue(value: unknown, fallback: string): string {
	if (typeof value !== 'string') {
		return fallback;
	}
	const trimmed = value.trim();
	return trimmed || fallback;
}

function sanitizeDescription(value: unknown): string {
	if (typeof value !== 'string') {
		return '';
	}
	return value.trim().slice(0, 50);
}

function buildKeySetModel(keys: Record<string, unknown>[]): string {
	return JSON.stringify({
		keys
	});
}

function buildManualKeyModel(publicKey: string, algorithm: string, keyType: string, claims?: Record<string, unknown>): string {
	const normalizedClaims = claims ? { ...claims } : {};
	const modelKey = {
		kty: sanitizeClaimValue(normalizedClaims.kty, keyType),
		n: sanitizeClaimValue(normalizedClaims.n, ''),
		e: sanitizeClaimValue(normalizedClaims.e, 'AQAB'),
		use: sanitizeClaimValue(normalizedClaims.use, 'sig'),
		alg: sanitizeClaimValue(normalizedClaims.alg, algorithm),
		kid: sanitizeClaimValue(normalizedClaims.kid, 'key1'),
		typ: sanitizeClaimValue(normalizedClaims.typ, 'JWT'),
		key: normalizePemInput(publicKey)
	};
	return buildKeySetModel([modelKey]);
}

/**
 * Key Storage Manager
 * Handles persisting and retrieving validation keys from VS Code's storage
 */
export class KeyStorageManager {
	constructor(private readonly context: vscode.ExtensionContext) {}

	/**
	 * Get all stored validation keys
	 */
	async getKeys(): Promise<ValidationKey[]> {
		const keys = this.context.globalState.get<ValidationKey[]>(STORAGE_KEY, []);
		return keys;
	}

	/**
	 * Get a specific key by ID
	 */
	async getKeyById(id: string): Promise<ValidationKey | undefined> {
		const keys = await this.getKeys();
		return keys.find(k => k.id === id);
	}

	/**
	 * Add a new manual validation key
	 */
	async addManualKey(name: string, publicKey: string, algorithm: string = 'RS256', keyType: string = 'RSA', claims?: Record<string, unknown>, description?: string): Promise<ManualValidationKey> {
		const key: ManualValidationKey = {
			id: generateKeyId(),
			name,
			description: sanitizeDescription(description),
			source: KeySource.Manual,
			keyData: encodeToBase64(buildManualKeyModel(publicKey, algorithm, keyType, claims)),
			createdAt: Date.now()
		};

		const keys = await this.getKeys();
		keys.push(key);
		await this.context.globalState.update(STORAGE_KEY, keys);

		return key;
	}

	/**
	 * Add a new URL-based validation key
	 */
	async addURLKey(
		name: string,
		url: string,
		refreshPeriod: RefreshPeriod,
		jwksKeys: Record<string, unknown>[],
		description?: string
	): Promise<URLValidationKey> {
		const now = Date.now();
		const key: URLValidationKey = {
			id: generateKeyId(),
			name,
			description: sanitizeDescription(description),
			source: KeySource.URL,
			url,
			refreshPeriod,
			keyData: encodeToBase64(buildKeySetModel(jwksKeys)),
			createdAt: now,
			lastFetchedAt: now,
			nextRefreshAt: calculateNextRefresh(refreshPeriod, now)
		};

		const keys = await this.getKeys();
		keys.push(key);
		await this.context.globalState.update(STORAGE_KEY, keys);

		return key;
	}

	/**
	 * Add a new direct JWKS JSON validation key
	 */
	async addJWKSJsonKey(name: string, rawJwksJson: string, jwksKeys: Record<string, unknown>[], description?: string): Promise<JWKSJsonValidationKey> {
		const key: JWKSJsonValidationKey = {
			id: generateKeyId(),
			name,
			description: sanitizeDescription(description),
			source: KeySource.JWKSJson,
			rawJwksJson,
			keyData: encodeToBase64(buildKeySetModel(jwksKeys)),
			createdAt: Date.now()
		};

		const keys = await this.getKeys();
		keys.push(key);
		await this.context.globalState.update(STORAGE_KEY, keys);

		return key;
	}

	/**
	 * Update an existing URL-based key with new key data
	 */
	async updateURLKey(id: string, jwksKeys: Record<string, unknown>[]): Promise<URLValidationKey | undefined> {
		const keys = await this.getKeys();
		const keyIndex = keys.findIndex(k => k.id === id);
		
		if (keyIndex === -1) {
			return undefined;
		}

		const key = keys[keyIndex];
		if (key.source !== KeySource.URL) {
			throw new Error('Cannot update non-URL key with refresh logic');
		}

		const urlKey = key as URLValidationKey;
		const now = Date.now();
		urlKey.keyData = encodeToBase64(buildKeySetModel(jwksKeys));
		urlKey.lastFetchedAt = now;
		urlKey.nextRefreshAt = calculateNextRefresh(urlKey.refreshPeriod, now);

		await this.context.globalState.update(STORAGE_KEY, keys);
		return urlKey;
	}

	/**
	 * Update URL key editable settings without changing fetched key material
	 */
	async updateURLKeySettings(id: string, name: string, refreshPeriod: RefreshPeriod, description?: string): Promise<URLValidationKey | undefined> {
		const keys = await this.getKeys();
		const keyIndex = keys.findIndex(k => k.id === id);

		if (keyIndex === -1) {
			return undefined;
		}

		const key = keys[keyIndex];
		if (key.source !== KeySource.URL) {
			throw new Error('Cannot update URL settings for a manual key');
		}

		const urlKey = key as URLValidationKey;
		urlKey.name = name;
		if (description !== undefined) {
			urlKey.description = sanitizeDescription(description);
		}
		urlKey.refreshPeriod = refreshPeriod;
		urlKey.nextRefreshAt = calculateNextRefresh(refreshPeriod, Date.now());

		await this.context.globalState.update(STORAGE_KEY, keys);
		return urlKey;
	}

	/**
	 * Update an existing manual key
	 */
	async updateManualKey(id: string, name: string, publicKey: string, algorithm: string = 'RS256', keyType: string = 'RSA', claims?: Record<string, unknown>, description?: string): Promise<ManualValidationKey | undefined> {
		const keys = await this.getKeys();
		const keyIndex = keys.findIndex(k => k.id === id);
		
		if (keyIndex === -1) {
			return undefined;
		}

		const key = keys[keyIndex];
		if (key.source !== KeySource.Manual) {
			throw new Error('Cannot update URL key as manual key');
		}

		const manualKey = key as ManualValidationKey;
		manualKey.name = name;
		if (description !== undefined) {
			manualKey.description = sanitizeDescription(description);
		}
		manualKey.keyData = encodeToBase64(buildManualKeyModel(publicKey, algorithm, keyType, claims));

		await this.context.globalState.update(STORAGE_KEY, keys);
		return manualKey;
	}

	async updateJWKSJsonKey(id: string, name: string, rawJwksJson: string, jwksKeys: Record<string, unknown>[], description?: string): Promise<JWKSJsonValidationKey | undefined> {
		const keys = await this.getKeys();
		const keyIndex = keys.findIndex(k => k.id === id);

		if (keyIndex === -1) {
			return undefined;
		}

		const key = keys[keyIndex];
		if (key.source !== KeySource.JWKSJson) {
			throw new Error('Cannot update non-JWKS JSON key with JWKS data');
		}

		const jwksKey = key as JWKSJsonValidationKey;
		jwksKey.name = name;
		if (description !== undefined) {
			jwksKey.description = sanitizeDescription(description);
		}
		jwksKey.rawJwksJson = rawJwksJson;
		jwksKey.keyData = encodeToBase64(buildKeySetModel(jwksKeys));

		await this.context.globalState.update(STORAGE_KEY, keys);
		return jwksKey;
	}

	/**
	 * Update only the display name of an existing key
	 */
	async updateKeyName(id: string, name: string, description?: string): Promise<ValidationKey | undefined> {
		const keys = await this.getKeys();
		const keyIndex = keys.findIndex(k => k.id === id);

		if (keyIndex === -1) {
			return undefined;
		}

		keys[keyIndex].name = name;
		if (description !== undefined) {
			keys[keyIndex].description = sanitizeDescription(description);
		}
		await this.context.globalState.update(STORAGE_KEY, keys);
		return keys[keyIndex];
	}

	/**
	 * Delete a validation key
	 */
	async deleteKey(id: string): Promise<boolean> {
		const keys = await this.getKeys();
		const filteredKeys = keys.filter(k => k.id !== id);
		
		if (filteredKeys.length === keys.length) {
			return false; // Key not found
		}

		await this.context.globalState.update(STORAGE_KEY, filteredKeys);
		return true;
	}

	/**
	 * Clear all keys (useful for testing/reset)
	 */
	async clearAllKeys(): Promise<void> {
		await this.context.globalState.update(STORAGE_KEY, []);
	}

	/**
	 * Get the decoded public key data
	 */
	getDecodedKey(key: ValidationKey): string {
		return decodeFromBase64(key.keyData);
	}
}
