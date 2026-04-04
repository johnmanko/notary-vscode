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
 * Refresh period options for URL-based keys
 */
export enum RefreshPeriod {
	Daily = 'daily',
	Weekly = 'weekly',
	Monthly = 'monthly'
}

/**
 * Source type of the validation key
 */
export enum KeySource {
	Manual = 'manual',
	URL = 'url'
}

/**
 * Base interface for all validation keys
 */
export interface ValidationKey {
	/** Unique identifier for the key */
	id: string;
	/** User-provided name for the key */
	name: string;
	/** Source type of the key */
	source: KeySource;
	/** Base64-encoded public key */
	keyData: string;
	/** Timestamp when the key was created */
	createdAt: number;
}

/**
 * Manual entry validation key
 */
export interface ManualValidationKey extends ValidationKey {
	source: KeySource.Manual;
}

/**
 * URL-based validation key with refresh configuration
 */
export interface URLValidationKey extends ValidationKey {
	source: KeySource.URL;
	/** OpenID Connect Keys URL */
	url: string;
	/** How often to refresh the key */
	refreshPeriod: RefreshPeriod;
	/** Timestamp of last successful fetch */
	lastFetchedAt: number;
	/** Timestamp when next refresh is needed */
	nextRefreshAt: number;
}

/**
 * Type guard to check if a key is URL-based
 */
export function isURLKey(key: ValidationKey): key is URLValidationKey {
	return key.source === KeySource.URL;
}

/**
 * Type guard to check if a key is manual
 */
export function isManualKey(key: ValidationKey): key is ManualValidationKey {
	return key.source === KeySource.Manual;
}

/**
 * Calculate milliseconds for a refresh period
 */
export function getRefreshPeriodMs(period: RefreshPeriod): number {
	switch (period) {
		case RefreshPeriod.Daily:
			return 24 * 60 * 60 * 1000;
		case RefreshPeriod.Weekly:
			return 7 * 24 * 60 * 60 * 1000;
		case RefreshPeriod.Monthly:
			return 30 * 24 * 60 * 60 * 1000;
	}
}

/**
 * Check if a URL-based key needs to be refreshed
 */
export function needsRefresh(key: URLValidationKey): boolean {
	return Date.now() >= key.nextRefreshAt;
}

/**
 * Calculate next refresh timestamp based on period
 */
export function calculateNextRefresh(period: RefreshPeriod, fromTime: number = Date.now()): number {
	return fromTime + getRefreshPeriodMs(period);
}
