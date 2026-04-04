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
import { ValidationKey, isURLKey, needsRefresh, RefreshPeriod } from '../types/keyManagement';
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

function decodeBase64UrlToBuffer(value: string): Buffer {
	const base64 = value.replaceAll('-', '+').replaceAll('_', '/');
	const pad = base64.length % 4;
	const padded = pad === 0 ? base64 : base64 + '='.repeat(4 - pad);
	return Buffer.from(padded, 'base64');
}

function tryDecodeNClaim(jwk: Record<string, unknown>): string {
	const n = jwk.n;
	if (typeof n !== 'string') {
		return '';
	}
	try {
		const bytes = decodeBase64UrlToBuffer(n);
		return bytes.toString('hex');
	} catch {
		return '';
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
	async addManualKey(name: string, publicKey: string, algorithm: string = 'RS256', keyType: string = 'RSA'): Promise<KeyOperationResult> {
		try {
			// Validate input
			if (!name || name.trim().length === 0) {
				return { success: false, error: 'Key name is required' };
			}

			if (!publicKey || publicKey.trim().length === 0) {
				return { success: false, error: 'Public key is required' };
			}

			const pemValidation = validateManualPemInput(publicKey);
			if (!pemValidation.valid) {
				return { success: false, error: pemValidation.error || 'Invalid public key format' };
			}

			const normalizedKeyType = keyType.trim().toUpperCase() || 'RSA';
			const key = await this.storageManager.addManualKey(name.trim(), pemValidation.normalized, algorithm.trim() || 'RS256', normalizedKeyType);
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
		refreshPeriod: RefreshPeriod
	): Promise<KeyOperationResult> {
		try {
			// Validate input
			if (!name || name.trim().length === 0) {
				return { success: false, error: 'Key name is required' };
			}

			if (!url || url.trim().length === 0) {
				return { success: false, error: 'URL is required' };
			}

			// Fetch the key from the URL
			const fetchResult = await fetchOIDCKeys(url.trim());
			if (!fetchResult.success || !fetchResult.publicKey) {
				return {
					success: false,
					error: fetchResult.error || 'Failed to fetch key from URL'
				};
			}

			// Store the key
			const key = await this.storageManager.addURLKey(
				name.trim(),
				url.trim(),
				refreshPeriod,
				fetchResult.publicKey
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
			if (!fetchResult.success || !fetchResult.publicKey) {
				return {
					success: false,
					error: fetchResult.error || 'Failed to fetch key from URL'
				};
			}

			// Update the stored key
			const updatedKey = await this.storageManager.updateURLKey(id, fetchResult.publicKey);
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
	async updateManualKey(id: string, name: string, publicKey: string, algorithm: string = 'RS256', keyType: string = 'RSA'): Promise<{ success: boolean; error?: string }> {
		try {
			const pemValidation = validateManualPemInput(publicKey);
			if (!pemValidation.valid) {
				return { success: false, error: pemValidation.error || 'Invalid public key format' };
			}

			const normalizedKeyType = keyType.trim().toUpperCase() || 'RSA';
			const result = await this.storageManager.updateManualKey(id, name, pemValidation.normalized, algorithm, normalizedKeyType);
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
	async updateKeyName(id: string, name: string): Promise<{ success: boolean; error?: string }> {
		try {
			if (!name || name.trim().length === 0) {
				return { success: false, error: 'Key name is required' };
			}

			const result = await this.storageManager.updateKeyName(id, name.trim());
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
	async updateURLKeySettings(id: string, name: string, refreshPeriod: RefreshPeriod): Promise<{ success: boolean; error?: string }> {
		try {
			if (!name || name.trim().length === 0) {
				return { success: false, error: 'Key name is required' };
			}

			const key = await this.storageManager.getKeyById(id);
			if (!key) {
				return { success: false, error: 'Key not found' };
			}
			if (!isURLKey(key)) {
				return { success: false, error: 'Cannot update URL settings for a manual key' };
			}

			const result = await this.storageManager.updateURLKeySettings(id, name.trim(), refreshPeriod);
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

	getPublicKeyForValidation(key: ValidationKey): string {
		const decoded = this.getDecodedKey(key);
		const parsed = parseStoredJson(decoded);

		if (!parsed) {
			return decoded;
		}

		if (isURLKey(key)) {
			try {
				return crypto.createPublicKey({ key: parsed as crypto.JsonWebKey, format: 'jwk' })
					.export({ type: 'spki', format: 'pem' })
					.toString();
			} catch {
				return decoded;
			}
		}

		const modelKey = parsed.key;
		if (typeof modelKey === 'string') {
			return modelKey;
		}

		return decoded;
	}

	getKeyEditorData(key: ValidationKey): KeyEditorData {
		const decoded = this.getDecodedKey(key);
		const parsed = parseStoredJson(decoded);

		if (!parsed) {
			return {
				claims: {},
				decodedKey: decoded,
				rawJson: isURLKey(key) ? decoded : undefined
			};
		}

		let decodedKey = '';
		if (isURLKey(key)) {
			try {
				decodedKey = crypto.createPublicKey({ key: parsed as crypto.JsonWebKey, format: 'jwk' })
					.export({ type: 'spki', format: 'pem' })
					.toString();
			} catch {
				decodedKey = tryDecodeNClaim(parsed);
			}
		} else {
			decodedKey = typeof parsed.key === 'string' ? parsed.key : '';
		}

		return {
			claims: parsed,
			rawJson: isURLKey(key) ? decoded : undefined,
			decodedKey,
			algorithm: typeof parsed.alg === 'string' ? parsed.alg : undefined,
			typ: typeof parsed.typ === 'string' ? parsed.typ : undefined,
			kid: typeof parsed.kid === 'string' ? parsed.kid : undefined
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
