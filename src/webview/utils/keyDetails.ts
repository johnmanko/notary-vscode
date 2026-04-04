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

// Webview script for key details panel.
// Compiled by esbuild to media/keyDetails.js — runs in the webview (browser) context.

declare function acquireVsCodeApi(): {
	postMessage(message: unknown): void;
};

// VS Code API
const vscodeApi = acquireVsCodeApi();

// DOM Elements
const keyTitle = document.getElementById('key-title')!;
const keySource = document.getElementById('key-source')!;
const keyNameInput = document.getElementById('key-name') as HTMLInputElement;
const keyDataTextarea = document.getElementById('key-data') as HTMLTextAreaElement;
const publicKeySection = document.getElementById('public-key-section')!;
const claimsFields = document.getElementById('claims-fields')!;
const rawJsonSection = document.getElementById('raw-json-section')!;
const rawJsonToggle = document.getElementById('raw-json-toggle') as HTMLButtonElement;
const rawJsonContent = document.getElementById('raw-json-content')!;
const sourceSelectionSection = document.getElementById('source-selection-section')!;
const sourceUrlRadio = document.getElementById('source-url') as HTMLInputElement;
const sourceManualRadio = document.getElementById('source-manual') as HTMLInputElement;
const urlSection = document.getElementById('url-section')!;
const keyUrlReadonly = document.getElementById('key-url-readonly')!;
const keyUrlInput = document.getElementById('key-url-input') as HTMLInputElement;
const urlHelp = document.getElementById('url-help')!;
const refreshSection = document.getElementById('refresh-section')!;
const refreshPeriodReadonly = document.getElementById('refresh-period-readonly')!;
const refreshPeriodSelect = document.getElementById('refresh-period-select') as HTMLSelectElement;
const manualMetadataSection = document.getElementById('manual-metadata-section')!;
const metadataSection = document.getElementById('metadata-section')!;
const createdAtSpan = document.getElementById('created-at')!;
const lastFetchedItem = document.getElementById('last-fetched-item')!;
const lastFetchedSpan = document.getElementById('last-fetched')!;
const nextRefreshItem = document.getElementById('next-refresh-item')!;
const nextRefreshSpan = document.getElementById('next-refresh')!;
const errorBanner = document.getElementById('error-banner')!;
const saveBtn = document.getElementById('save-btn')!;
const refreshBtn = document.getElementById('refresh-btn')!;
const deleteBtn = document.getElementById('delete-btn')!;

let currentKey: any = null;
let isUrlKey = false;
let isCreateMode = false;
let currentClaims: Record<string, unknown> = {};

const CLAIM_NAME_DICTIONARY: Record<string, string> = {
	alg: 'Algorithm',
	typ: 'Type',
	kid: 'Key ID',
	kty: 'Key Type',
	use: 'Public Key Use',
	n: 'Modulus',
	e: 'Exponent',
	x: 'X Coordinate',
	y: 'Y Coordinate',
	crv: 'Curve',
	x5c: 'X.509 Certificate Chain',
	x5t: 'X.509 SHA-1 Thumbprint',
	'x5t#S256': 'X.509 SHA-256 Thumbprint',
	key: 'Public Key'
};

const MANUAL_EDITABLE_CLAIMS = new Set(['alg', 'kty']);

// Safe initial UI state until extension sends createMode/keyData.
refreshBtn.style.display = 'none';
deleteBtn.style.display = 'none';
rawJsonSection.style.display = 'none';

// Event Listeners
sourceUrlRadio.addEventListener('change', updateFormBasedOnSource);
sourceManualRadio.addEventListener('change', updateFormBasedOnSource);

claimsFields.addEventListener('input', (event) => {
	const target = event.target as HTMLInputElement;
	if (!target || !target.dataset.claimKey) {
		return;
	}
	currentClaims[target.dataset.claimKey] = target.value;
});

saveBtn.addEventListener('click', () => {
	if (isCreateMode) {
		handleCreateKey();
	} else {
		handleUpdateKey();
	}
});

refreshBtn.addEventListener('click', () => {
	vscodeApi.postMessage({ type: 'refreshKey' });
});

deleteBtn.addEventListener('click', () => {
	vscodeApi.postMessage({ type: 'deleteKey', id: currentKey?.id });
});

rawJsonToggle.addEventListener('click', () => {
	const visible = rawJsonContent.style.display === 'block';
	rawJsonContent.style.display = visible ? 'none' : 'block';
	rawJsonToggle.textContent = visible ? 'Show Raw JSON' : 'Hide Raw JSON';
});

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

function updateFormBasedOnSource(): void {
	const isUrl = sourceUrlRadio.checked;
	
	if (isUrl) {
		// Show URL fields
		urlSection.style.display = 'block';
		keyUrlInput.style.display = 'block';
		keyUrlReadonly.style.display = 'none';
		urlHelp.style.display = 'block';
		
		refreshSection.style.display = 'block';
		refreshPeriodSelect.style.display = 'block';
		refreshPeriodReadonly.style.display = 'none';
		
		// Disable key data textarea (will be fetched from URL)
		keyDataTextarea.disabled = true;
		keyDataTextarea.placeholder = 'Key will be fetched from URL';
		publicKeySection.style.display = isCreateMode ? 'none' : 'block';
		manualMetadataSection.style.display = isCreateMode ? 'none' : 'block';
	} else {
		// Hide URL fields
		urlSection.style.display = 'none';
		urlHelp.style.display = 'none';
		refreshSection.style.display = 'none';
		
		// Enable key data textarea
		keyDataTextarea.disabled = false;
		keyDataTextarea.placeholder = 'Paste PEM-encoded public key here';
		publicKeySection.style.display = 'block';
		manualMetadataSection.style.display = 'block';
		if (typeof currentClaims.alg !== 'string' || !currentClaims.alg) {
			currentClaims.alg = 'RS256';
		}
		if (typeof currentClaims.kty !== 'string' || !currentClaims.kty) {
			currentClaims.kty = 'RSA';
		}
		if (typeof currentClaims.typ !== 'string' || !currentClaims.typ) {
			currentClaims.typ = 'JWT';
		}
		if (typeof currentClaims.kid !== 'string' || !currentClaims.kid) {
			currentClaims.kid = 'key1';
		}
		renderClaims(currentClaims, false);
	}
}

function handleCreateKey(): void {
	const name = keyNameInput.value.trim();
	const algorithm = (typeof currentClaims.alg === 'string' && currentClaims.alg.trim()) ? currentClaims.alg.trim() : 'RS256';
	const keyType = (typeof currentClaims.kty === 'string' && currentClaims.kty.trim()) ? currentClaims.kty.trim() : 'RSA';
	
	if (!name) {
		showError('Key name is required');
		return;
	}

	if (sourceUrlRadio.checked) {
		// Create URL key
		const url = keyUrlInput.value.trim();
		if (!url) {
			showError('URL is required');
			return;
		}
		
		const refreshPeriod = refreshPeriodSelect.value;
		vscodeApi.postMessage({
			type: 'createURLKey',
			name,
			url,
			refreshPeriod
		});
	} else {
		// Create manual key
		const validation = validateManualPemInput(keyDataTextarea.value);
		if (!validation.valid) {
			showError(validation.error || 'Invalid public key');
			return;
		}
		
		vscodeApi.postMessage({
			type: 'createManualKey',
			name,
			keyData: validation.normalized,
			algorithm,
			keyType
		});
	}
}

function handleUpdateKey(): void {
	const name = keyNameInput.value.trim();
	const algorithm = (typeof currentClaims.alg === 'string' && currentClaims.alg.trim()) ? currentClaims.alg.trim() : 'RS256';
	const keyType = (typeof currentClaims.kty === 'string' && currentClaims.kty.trim()) ? currentClaims.kty.trim() : 'RSA';

	if (!name) {
		showError('Key name is required');
		return;
	}

	if (!isUrlKey) {
		const validation = validateManualPemInput(keyDataTextarea.value);
		if (!validation.valid) {
			showError(validation.error || 'Invalid public key');
			return;
		}

		vscodeApi.postMessage({
			type: 'updateKey',
			name,
			keyData: validation.normalized,
			algorithm,
			keyType
		});
		return;
	}

	vscodeApi.postMessage({
		type: 'updateKey',
		name,
		keyData: keyDataTextarea.value,
		algorithm,
		refreshPeriod: refreshPeriodSelect.value
	});
}

// Handle messages from extension
window.addEventListener('message', (event: MessageEvent<{
	type: string;
	key?: any;
	error?: string;
}>) => {
	const message = event.data;

	if (message.type === 'createMode') {
		enterCreateMode();
	} else if (message.type === 'keyData' && message.key) {
		loadKeyData(message.key);
	} else if (message.type === 'error' && message.error) {
		showError(message.error);
	}
});

function enterCreateMode(): void {
	isCreateMode = true;
	currentKey = null;
	isUrlKey = false;
	currentClaims = {
		alg: 'RS256',
		kty: 'RSA',
		typ: 'JWT',
		kid: 'key1'
	};
	
	// Update title and UI for create mode
	keyTitle.textContent = 'Add New Validation Key';
	keySource.style.display = 'none';
	
	// Show source selection
	sourceSelectionSection.style.display = 'block';
	
	// Hide metadata section (no creation date yet)
	metadataSection.style.display = 'none';
	claimsFields.innerHTML = '';
	publicKeySection.style.display = 'block';
	rawJsonSection.style.display = 'none';
	urlSection.style.display = 'none';
	refreshSection.style.display = 'none';
	lastFetchedItem.style.display = 'none';
	nextRefreshItem.style.display = 'none';
	rawJsonContent.style.display = 'none';
	rawJsonToggle.textContent = 'Show Raw JSON';
	
	// Update save button text
	saveBtn.textContent = 'Add Key';
	refreshBtn.style.display = 'none';
	
	// Hide delete button (nothing to delete yet)
	deleteBtn.style.display = 'none';

	// Default new entry to Manual source for clearer UX.
	sourceManualRadio.checked = true;
	sourceUrlRadio.checked = false;
	renderClaims(currentClaims, false);
	
	// Initialize form state
	updateFormBasedOnSource();
}

function renderClaims(claims: Record<string, unknown> | undefined, readOnly: boolean): void {
	if (!claims || Object.keys(claims).length === 0) {
		claimsFields.innerHTML = '';
		return;
	}

	claimsFields.innerHTML = Object.entries(claims).map(([key, value]) => {
		const commonName = CLAIM_NAME_DICTIONARY[key] || key.toUpperCase();
		const label = `${commonName} (${key})`;
		let displayValue = '';
		let editable = !readOnly && MANUAL_EDITABLE_CLAIMS.has(key);
		if (key === 'key') {
			displayValue = '(shown in Public Key section)';
			editable = false;
		} else if (typeof value === 'string') {
			displayValue = value;
		} else {
			displayValue = JSON.stringify(value);
			editable = false;
		}

		const valueHtml = `<input class="input" data-claim-key="${escapeHtml(key)}" value="${escapeHtml(displayValue)}" ${editable ? '' : 'disabled'} />`;
		return `
			<div class="metadata-item">
				<span class="metadata-label">${escapeHtml(label)}:</span>
				${valueHtml}
			</div>
		`;
	}).join('');
}

function escapeHtml(value: string): string {
	return value
		.replaceAll('&', '&amp;')
		.replaceAll('<', '&lt;')
		.replaceAll('>', '&gt;')
		.replaceAll('"', '&quot;')
		.replaceAll("'", '&#39;');
}

function loadKeyData(key: any): void {
	currentKey = key;
	isUrlKey = key.source === 'url';
	isCreateMode = false;

	// Reset mode-specific sections before applying current key mode.
	urlSection.style.display = 'none';
	refreshSection.style.display = 'none';
	rawJsonSection.style.display = 'none';
	rawJsonContent.style.display = 'none';
	rawJsonToggle.textContent = 'Show Raw JSON';
	lastFetchedItem.style.display = 'none';
	nextRefreshItem.style.display = 'none';

	// Update header
	keyTitle.textContent = key.name;
	keySource.textContent = key.source.toUpperCase();
	keySource.className = `key-badge ${key.source}`;
	keySource.style.display = 'inline-block';

	// Hide source selection (not in create mode)
	sourceSelectionSection.style.display = 'none';
	sourceUrlRadio.checked = isUrlKey;
	sourceManualRadio.checked = !isUrlKey;

	// Update form
	keyNameInput.value = key.name;
	keyDataTextarea.value = key.keyData || '';
	publicKeySection.style.display = 'block';
	currentClaims = (key.claims && typeof key.claims === 'object') ? { ...key.claims } : {};
	renderClaims(currentClaims, isUrlKey);

	// Disable editing for URL keys
	if (isUrlKey) {
		keyNameInput.disabled = false;
		keyDataTextarea.disabled = true;
		saveBtn.style.display = 'inline-block';
		saveBtn.textContent = 'Save Name';
		refreshBtn.style.display = 'inline-block';

		// Show URL info (readonly)
		urlSection.style.display = 'block';
		keyUrlReadonly.textContent = key.url || '';
		keyUrlReadonly.style.display = 'block';
		keyUrlInput.style.display = 'none';
		urlHelp.style.display = 'none';

		refreshSection.style.display = 'block';
		refreshPeriodReadonly.style.display = 'none';
		refreshPeriodSelect.style.display = 'block';
		refreshPeriodSelect.value = key.refreshPeriod || 'weekly';
		manualMetadataSection.style.display = 'block';
		rawJsonSection.style.display = 'block';
		if (typeof key.rawJson === 'string' && key.rawJson.trim()) {
			try {
				rawJsonContent.textContent = JSON.stringify(JSON.parse(key.rawJson), null, 2);
			} catch {
				rawJsonContent.textContent = key.rawJson;
			}
		} else {
			rawJsonContent.textContent = 'Raw JSON is not available for this key.';
		}
		rawJsonContent.style.display = 'none';
		rawJsonToggle.textContent = 'Show Raw JSON';

		// Show fetch times
		if (key.lastFetchedAt) {
			lastFetchedItem.style.display = 'block';
			lastFetchedSpan.textContent = formatDateTime(key.lastFetchedAt);
		}

		if (key.nextRefreshAt) {
			nextRefreshItem.style.display = 'block';
			nextRefreshSpan.textContent = formatDateTime(key.nextRefreshAt);
		}
	} else {
		keyNameInput.disabled = false;
		keyDataTextarea.disabled = false;
		if (typeof currentClaims.alg !== 'string' || !currentClaims.alg) {
			currentClaims.alg = 'RS256';
		}
		if (typeof currentClaims.kty !== 'string' || !currentClaims.kty) {
			currentClaims.kty = 'RSA';
		}
		if (typeof currentClaims.typ !== 'string' || !currentClaims.typ) {
			currentClaims.typ = 'JWT';
		}
		if (typeof currentClaims.kid !== 'string' || !currentClaims.kid) {
			currentClaims.kid = 'key1';
		}
		renderClaims(currentClaims, false);
		saveBtn.style.display = 'inline-block';
		saveBtn.textContent = 'Save Changes';
		refreshBtn.style.display = 'none';

		urlSection.style.display = 'none';
		refreshSection.style.display = 'none';
		manualMetadataSection.style.display = 'block';
		rawJsonSection.style.display = 'none';
		rawJsonContent.style.display = 'none';
		rawJsonToggle.textContent = 'Show Raw JSON';
		lastFetchedItem.style.display = 'none';
		nextRefreshItem.style.display = 'none';
	}

	// Show metadata section and created date
	metadataSection.style.display = 'block';
	createdAtSpan.textContent = formatDateTime(key.createdAt);
	
	// Show delete button
	deleteBtn.style.display = 'inline-block';
}

function showError(message: string): void {
	errorBanner.textContent = message;
	errorBanner.classList.add('visible');
	setTimeout(() => {
		errorBanner.classList.remove('visible');
	}, 5000);
}

function formatDateTime(timestamp: number): string {
	return new Date(timestamp).toLocaleString([], {
		year: 'numeric',
		month: 'short',
		day: 'numeric',
		hour: '2-digit',
		minute: '2-digit'
	});
}

function capitalizeFirst(str: string): string {
	return str.charAt(0).toUpperCase() + str.slice(1);
}

// Notify extension that webview is ready to receive initial state.
vscodeApi.postMessage({ type: 'ready' });
