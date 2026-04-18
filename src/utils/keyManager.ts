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
import { ValidationKey, isURLKey, isJWKSJsonKey, needsRefresh, RefreshPeriod } from '../types/keyManagement';
import { KeyStorageManager } from './keyStorage';
import { FetchResult, fetchOIDCKeys } from './oidcKeyFetcher';
import {
	buildKeyEditorData,
	getErrorMessage,
	getValidationMaterialFromDecoded,
	isJwkObject,
	normalizeDescription,
	normalizeManualClaims,
	parseJWKSJsonInput,
	validateManualClaims,
	validateManualPemInput
} from './keyManagerHelpers';

export type { KeyEditorData, ValidationKeyMaterial } from './keyManagerHelpers';

/**
 * Result of a key operation
 */
export interface KeyOperationResult {
	success: boolean;
	key?: ValidationKey;
	error?: string;
}

type KeyStorageLike = Pick<
	KeyStorageManager,
	'getKeys' |
	'getKeyById' |
	'addManualKey' |
	'addURLKey' |
	'addJWKSJsonKey' |
	'updateURLKey' |
	'updateURLKeySettings' |
	'updateManualKey' |
	'updateJWKSJsonKey' |
	'updateKeyName' |
	'deleteKey' |
	'getDecodedKey'
>;

export interface KeyManagerDependencies {
	storageManager?: KeyStorageLike;
	fetchKeys?: (url: string) => Promise<FetchResult>;
}

/**
 * Key Manager
 * Coordinates key storage, fetching, and refresh logic
 */
export class KeyManager {
	private readonly storageManager: KeyStorageLike;
	private readonly fetchKeys: (url: string) => Promise<FetchResult>;

	constructor(context: vscode.ExtensionContext, dependencies: KeyManagerDependencies = {}) {
		this.storageManager = dependencies.storageManager ?? new KeyStorageManager(context);
		this.fetchKeys = dependencies.fetchKeys ?? fetchOIDCKeys;
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
				error: getErrorMessage(error, 'Failed to add manual key')
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
			const fetchResult = await this.fetchKeys(url.trim());
			if (!fetchResult.success || !fetchResult.jwks) {
				return {
					success: false,
					error: fetchResult.error || 'Failed to fetch key from URL'
				};
			}

			const jwkObjects = fetchResult.jwks.keys.filter(key => isJwkObject(key));
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
				error: getErrorMessage(error, 'Failed to add URL key')
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
				error: getErrorMessage(error, 'Failed to add JWKS JSON key')
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
				error: getErrorMessage(error, 'Failed to update JWKS JSON key')
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
			const fetchResult = await this.fetchKeys(key.url);
			if (!fetchResult.success || !fetchResult.jwks) {
				return {
					success: false,
					error: fetchResult.error || 'Failed to fetch key from URL'
				};
			}

			const jwkObjects = fetchResult.jwks.keys.filter(key => isJwkObject(key));
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
				error: getErrorMessage(error, 'Failed to refresh key')
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
				error: getErrorMessage(error, 'Failed to get key')
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
				error: getErrorMessage(error, 'Failed to update key')
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
				error: getErrorMessage(error, 'Failed to update key name')
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
				error: getErrorMessage(error, 'Failed to update URL key settings')
			};
		}
	}

	/**
	 * Get the decoded public key data
	 */
	getDecodedKey(key: ValidationKey): string {
		return this.storageManager.getDecodedKey(key);
	}

	getValidationMaterial(key: ValidationKey, tokenKid?: string, selectedKeyRefOverride?: string) {
		const decoded = this.getDecodedKey(key);
		return getValidationMaterialFromDecoded(decoded, tokenKid, selectedKeyRefOverride);
	}

	getPublicKeyForValidation(key: ValidationKey): string {
		const material = this.getValidationMaterial(key);
		if (!material.success || !material.data) {
			return this.getDecodedKey(key);
		}
		return material.data.publicKey;
	}

	getKeyEditorData(key: ValidationKey) {
		const decoded = this.getDecodedKey(key);
		return buildKeyEditorData(key, decoded);
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
