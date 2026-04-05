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

import { getRawJsonToggleLabel } from '../utils';

declare function acquireVsCodeApi(): {
	postMessage(message: unknown): void;
};

// VS Code API
const vscodeApi = acquireVsCodeApi();

// DOM Elements
const keyTitle = document.getElementById('key-title')!;
const keySource = document.getElementById('key-source')!;
const keyNameInput = document.getElementById('key-name') as HTMLInputElement;
const keyDescriptionInput = document.getElementById('key-description') as HTMLInputElement;
const keyDescriptionCounter = document.getElementById('key-description-counter')!;
const keyDataTextarea = document.getElementById('key-data') as HTMLTextAreaElement;
const keyDataReadonly = document.getElementById('key-data-readonly')!;
const publicKeySection = document.getElementById('public-key-section')!;
const claimsFields = document.getElementById('claims-fields')!;
const rawJsonSection = document.getElementById('raw-json-section')!;
const rawJsonToggle = document.getElementById('raw-json-toggle') as HTMLButtonElement;
const rawJsonContent = document.getElementById('raw-json-content')!;
const sourceSelectionSection = document.getElementById('source-selection-section')!;
const sourceUrlRadio = document.getElementById('source-url') as HTMLInputElement;
const sourceJwksJsonRadio = document.getElementById('source-jwks-json') as HTMLInputElement;
const sourceManualRadio = document.getElementById('source-manual') as HTMLInputElement;
const urlSection = document.getElementById('url-section')!;
const keyUrlReadonly = document.getElementById('key-url-readonly')!;
const keyUrlInput = document.getElementById('key-url-input') as HTMLInputElement;
const urlHelp = document.getElementById('url-help')!;
const refreshSection = document.getElementById('refresh-section')!;
const refreshPeriodReadonly = document.getElementById('refresh-period-readonly')!;
const refreshPeriodSelect = document.getElementById('refresh-period-select') as HTMLSelectElement;
const jwksJsonSection = document.getElementById('jwks-json-section')!;
const jwksJsonInput = document.getElementById('jwks-json-input') as HTMLTextAreaElement;
const jwksJsonStatus = document.getElementById('jwks-json-status')!;
const manualMetadataSection = document.getElementById('manual-metadata-section')!;
const keySelectionSection = document.getElementById('key-selection-section')!;
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
let isJwksJsonKey = false;
let isCreateMode = false;
let currentClaims: Record<string, unknown> = {};
let modulusDerivationRequestId = 0;

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
	'x5t#S256': 'X.509 SHA-256 Thumbprint'
};

const DEFAULT_MANUAL_CLAIMS: Record<string, string> = {
	kty: 'RSA',
	n: '',
	e: 'AQAB',
	use: 'sig',
	alg: 'RS256',
	kid: 'key1'
};

const NON_EDITABLE_MANUAL_CLAIMS = new Set(['n']);

function ensureManualClaimDefaults(target: Record<string, unknown>): void {
	for (const [claimKey, defaultValue] of Object.entries(DEFAULT_MANUAL_CLAIMS)) {
		if (typeof target[claimKey] !== 'string' || !(target[claimKey] as string).trim()) {
			target[claimKey] = defaultValue;
		}
	}
}

function isBase64Url(value: string): boolean {
	return /^[A-Za-z0-9_-]+$/.test(value);
}

function decodeBase64UrlToBytes(value: string): Uint8Array {
	const base64 = value.replaceAll('-', '+').replaceAll('_', '/');
	const padLength = base64.length % 4;
	const padded = padLength === 0 ? base64 : base64 + '='.repeat(4 - padLength);
	const decoded = atob(padded);
	const bytes = new Uint8Array(decoded.length);
	for (let index = 0; index < decoded.length; index += 1) {
		bytes[index] = decoded.charCodeAt(index);
	}
	return bytes;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
	let result = 0n;
	for (const byte of bytes) {
		result = (result << 8n) | BigInt(byte);
	}
	return result;
}

function getExponentHint(value: string): { valid: boolean; message: string } {
	const trimmed = value.trim();
	if (!trimmed) {
		return { valid: false, message: 'Exponent (e) is required and must be Base64URL.' };
	}
	if (!isBase64Url(trimmed)) {
		return { valid: false, message: 'Exponent (e) must be Base64URL characters only: A-Z, a-z, 0-9, -, _' };
	}
	try {
		const bytes = decodeBase64UrlToBytes(trimmed);
		if (bytes.length === 0) {
			return { valid: false, message: 'Exponent (e) decoded to an empty value.' };
		}
		const numericValue = bytesToBigInt(bytes).toString(10);
		if (trimmed === 'AQAB') {
			return { valid: true, message: `AQAB is Base64URL for exponent ${numericValue} (common RSA public exponent).` };
		}
		return { valid: true, message: `Decoded exponent value: ${numericValue}` };
	} catch {
		return { valid: false, message: 'Exponent (e) is not valid Base64URL.' };
	}
}

function renderExponentHint(input: HTMLInputElement): void {
	const wrapper = input.closest('.metadata-item');
	if (!wrapper) {
		return;
	}

	let hint = wrapper.querySelector('.claim-hint') as HTMLDivElement | null;
	if (!hint) {
		hint = document.createElement('div');
		hint.className = 'claim-hint';
		wrapper.appendChild(hint);
	}

	const hintState = getExponentHint(input.value);
	hint.textContent = hintState.message;
	hint.classList.toggle('invalid', !hintState.valid);
	input.classList.toggle('input-invalid', !hintState.valid);
}

function renderModulusHint(message: string): void {
	const modulusInput = claimsFields.querySelector('input[data-claim-key="n"]') as HTMLInputElement | null;
	if (!modulusInput) {
		return;
	}
	const wrapper = modulusInput.closest('.metadata-item');
	if (!wrapper) {
		return;
	}

	let hint = wrapper.querySelector('.claim-hint') as HTMLDivElement | null;
	if (!hint) {
		hint = document.createElement('div');
		hint.className = 'claim-hint';
		wrapper.appendChild(hint);
	}

	hint.textContent = message;
}

function extractPemBodyBase64(normalizedPem: string): string | null {
	const supportedHeaders = [
		{ begin: '-----BEGIN PUBLIC KEY-----', end: '-----END PUBLIC KEY-----' },
		{ begin: '-----BEGIN RSA PUBLIC KEY-----', end: '-----END RSA PUBLIC KEY-----' }
	];

	const headerMatch = supportedHeaders.find(h => normalizedPem.includes(h.begin) && normalizedPem.includes(h.end));
	if (!headerMatch) {
		return null;
	}

	const beginIndex = normalizedPem.indexOf(headerMatch.begin) + headerMatch.begin.length;
	const endIndex = normalizedPem.indexOf(headerMatch.end);
	const base64Body = normalizedPem.slice(beginIndex, endIndex).replaceAll('\n', '').trim();
	return base64Body || null;
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let index = 0; index < binary.length; index += 1) {
		bytes[index] = binary.charCodeAt(index);
	}
	return bytes.buffer;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
	const bytes = new Uint8Array(buffer);
	let binary = '';
	for (let index = 0; index < bytes.length; index += 1) {
		binary += String.fromCharCode(bytes[index]);
	}
	return btoa(binary);
}

function chunkString(value: string, chunkSize: number): string[] {
	const chunks: string[] = [];
	for (let index = 0; index < value.length; index += chunkSize) {
		chunks.push(value.slice(index, index + chunkSize));
	}
	return chunks;
}

async function derivePublicKeyPemFromJwk(record: Record<string, unknown>): Promise<string | null> {
	if (!window.crypto?.subtle) {
		return null;
	}

	const kty = typeof record.kty === 'string' ? record.kty : '';
	const n = typeof record.n === 'string' ? record.n : '';
	const e = typeof record.e === 'string' ? record.e : '';
	if (kty !== 'RSA' || !n || !e) {
		return null;
	}

	const jwkRecord: Record<string, unknown> = {
		kty: 'RSA',
		n,
		e
	};

	const optionalFields = ['kid', 'alg', 'use'] as const;
	for (const field of optionalFields) {
		if (typeof record[field] === 'string') {
			jwkRecord[field] = record[field] as string;
		}
	}

	try {
		const key = await window.crypto.subtle.importKey(
			'jwk',
			jwkRecord as JsonWebKey,
			{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
			true,
			['verify']
		);
		const spki = await window.crypto.subtle.exportKey('spki', key);
		const base64Body = chunkString(arrayBufferToBase64(spki), 64).join('\n');
		return `-----BEGIN PUBLIC KEY-----\n${base64Body}\n-----END PUBLIC KEY-----`;
	} catch {
		return null;
	}
}

async function populateGroupedPublicKeys(keys: Record<string, unknown>[]): Promise<void> {
	await Promise.all(keys.map(async (jwk, index) => {
		const publicKeyDisplay = claimsFields.querySelector<HTMLElement>(`[data-group-public-key-index="${index}"]`);
		if (!publicKeyDisplay) {
			return;
		}

		const pem = await derivePublicKeyPemFromJwk(jwk);
		publicKeyDisplay.textContent = pem || 'Unavailable for this key.';
	}));
}

async function deriveModulusFromPem(normalizedPem: string): Promise<string> {
	const base64Body = extractPemBodyBase64(normalizedPem);
	if (!base64Body) {
		return '';
	}

	const spkiBuffer = base64ToArrayBuffer(base64Body);
	const algorithms: RsaHashedImportParams[] = [
		{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
		{ name: 'RSA-PSS', hash: 'SHA-256' },
		{ name: 'RSA-OAEP', hash: 'SHA-256' }
	];

	for (const algorithm of algorithms) {
		try {
			const key = await crypto.subtle.importKey('spki', spkiBuffer, algorithm, true, ['verify']);
			const jwk = await crypto.subtle.exportKey('jwk', key);
			if (jwk.kty === 'RSA' && typeof jwk.n === 'string') {
				return jwk.n;
			}
		} catch {
			// Try next algorithm profile.
		}
	}

	return '';
}

async function updateDerivedModulusClaim(): Promise<void> {
	if (sourceUrlRadio.checked || sourceJwksJsonRadio.checked) {
		return;
	}

	const requestId = ++modulusDerivationRequestId;
	const validation = validateManualPemInput(keyDataTextarea.value);
	if (!validation.valid) {
		currentClaims.n = '';
		const modulusInput = claimsFields.querySelector('input[data-claim-key="n"]') as HTMLInputElement | null;
		if (modulusInput) {
			modulusInput.value = '';
		}
		renderModulusHint('Managed by the Public Key PEM field and shown here when the PEM is valid RSA.');
		return;
	}

	const derivedModulus = await deriveModulusFromPem(validation.normalized);
	if (requestId !== modulusDerivationRequestId) {
		return;
	}

	currentClaims.n = derivedModulus;
	const modulusInput = claimsFields.querySelector('input[data-claim-key="n"]') as HTMLInputElement | null;
	if (modulusInput) {
		modulusInput.value = derivedModulus;
	}

	if (derivedModulus) {
		renderModulusHint('Derived Base64URL modulus (n) from the current PEM.');
	} else {
		renderModulusHint('Unable to derive RSA modulus from the current PEM.');
	}

	updateManualRawJsonPreview();
}

function validateManualClaims(claims: Record<string, unknown>): { valid: boolean; error?: string } {
	const exponentValue = typeof claims.e === 'string' ? claims.e.trim() : '';
	const hintState = getExponentHint(exponentValue);
	if (!hintState.valid) {
		return { valid: false, error: hintState.message };
	}
	return { valid: true };
}

function autoResizeTextarea(textarea: HTMLTextAreaElement): void {
	textarea.style.height = 'auto';
	textarea.style.height = `${Math.max(textarea.scrollHeight, 140)}px`;
}

function setJWKSStatus(message: string, state: 'success' | 'error' | 'info', visible: boolean = true): void {
	jwksJsonStatus.textContent = message;
	jwksJsonStatus.className = `status-line ${state}`;
	jwksJsonStatus.style.display = visible ? 'block' : 'none';
}

function setPublicKeyReadOnlyMode(readOnly: boolean): void {
	keyDataTextarea.readOnly = readOnly;
	keyDataTextarea.disabled = false;
	if (readOnly) {
		keyDataTextarea.classList.add('readonly-field');
		keyDataTextarea.style.display = 'none';
		keyDataReadonly.style.display = 'block';
		keyDataReadonly.textContent = keyDataTextarea.value || 'Public key is managed by this source.';
	} else {
		keyDataTextarea.classList.remove('readonly-field');
		keyDataTextarea.style.display = 'block';
		keyDataReadonly.style.display = 'none';
		keyDataReadonly.textContent = '';
	}
}

function renderPreferredKeyOptions(): void {
	keySelectionSection.style.display = 'none';
}

function getRawJsonShowLabel(): string {
	return getRawJsonToggleLabel(sourceManualRadio.checked, false);
}

function getRawJsonHideLabel(): string {
	return getRawJsonToggleLabel(sourceManualRadio.checked, true);
}

function buildManualKeyModelForPreview(): Record<string, unknown> {
	ensureManualClaimDefaults(currentClaims);
	return {
		kty: typeof currentClaims.kty === 'string' ? currentClaims.kty : 'RSA',
		n: typeof currentClaims.n === 'string' ? currentClaims.n : '',
		e: typeof currentClaims.e === 'string' ? currentClaims.e : 'AQAB',
		use: typeof currentClaims.use === 'string' ? currentClaims.use : 'sig',
		alg: typeof currentClaims.alg === 'string' ? currentClaims.alg : 'RS256',
		kid: typeof currentClaims.kid === 'string' ? currentClaims.kid : 'key1',
		typ: typeof currentClaims.typ === 'string' ? currentClaims.typ : 'JWT'
	};
}

function updateManualRawJsonPreview(): void {
	if (!sourceManualRadio.checked) {
		return;
	}

	const modelKey = buildManualKeyModelForPreview();
	const previewModel = {
		keys: [modelKey]
	};

	rawJsonSection.style.display = 'block';
	rawJsonContent.textContent = JSON.stringify(previewModel, null, 2);
	rawJsonContent.style.display = 'none';
	rawJsonToggle.textContent = getRawJsonShowLabel();
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function selectBestJwk(jwksObject: Record<string, unknown>): { key: Record<string, unknown>; index: number } | null {
	const keysValue = jwksObject.keys;
	if (!Array.isArray(keysValue)) {
		return null;
	}
	const jwkObjects = keysValue
		.map((value, index) => ({ value, index }))
		.filter((entry): entry is { value: Record<string, unknown>; index: number } => isRecord(entry.value));
	if (jwkObjects.length === 0) {
		return null;
	}
	const sigKey = jwkObjects.find(entry => entry.value.use === 'sig');
	return sigKey ? { key: sigKey.value, index: sigKey.index } : { key: jwkObjects[0].value, index: jwkObjects[0].index };
}

function parseJWKSInput(jwksJson: string): { valid: boolean; error?: string; selectedJwk?: Record<string, unknown>; selectedJwkIndex?: number; normalizedJson?: string } {
	const trimmed = jwksJson.trim();
	if (!trimmed) {
		return { valid: false, error: 'JWKS JSON is required' };
	}

	try {
		const parsed = JSON.parse(trimmed);
		if (!isRecord(parsed)) {
			return { valid: false, error: 'Invalid JWKS format: root must be an object' };
		}
		const selected = selectBestJwk(parsed);
		if (!selected) {
			return { valid: false, error: 'Invalid JWKS format: keys array is missing or empty' };
		}
		return {
			valid: true,
			selectedJwk: selected.key,
			selectedJwkIndex: selected.index,
			normalizedJson: JSON.stringify(parsed)
		};
	} catch {
		return { valid: false, error: 'Invalid JSON format for JWKS input' };
	}
}

function updateJWKSPreviewFromInput(): void {
	autoResizeTextarea(jwksJsonInput);
	if (!jwksJsonInput.value.trim()) {
		currentClaims = {};
		renderClaims(currentClaims, true);
		setJWKSStatus('Paste a JWKS JSON document to preview the selected key.', 'info', true);
		return;
	}

	const parsed = parseJWKSInput(jwksJsonInput.value);
	if (!parsed.valid || !parsed.selectedJwk) {
		currentClaims = {};
		renderClaims(currentClaims, true);
		setJWKSStatus(parsed.error || 'Invalid JWKS JSON input', 'error', true);
		return;
	}

	currentClaims = { ...parsed.selectedJwk };
	const keySet = parsed.normalizedJson ? extractKeySetFromRawJson(parsed.normalizedJson) : [];
	if (keySet.length > 0) {
		renderGroupedKeyClaims(keySet);
	} else {
		renderClaims(currentClaims, true);
	}
	const selectedKid = typeof parsed.selectedJwk.kid === 'string' && parsed.selectedJwk.kid.trim()
		? parsed.selectedJwk.kid
		: '(none)';
	const selectedAlg = typeof parsed.selectedJwk.alg === 'string' && parsed.selectedJwk.alg.trim()
		? parsed.selectedJwk.alg
		: '(unspecified)';
	const selectedKty = typeof parsed.selectedJwk.kty === 'string' && parsed.selectedJwk.kty.trim()
		? parsed.selectedJwk.kty
		: '(unknown)';
	const selectedIndex = typeof parsed.selectedJwkIndex === 'number' ? parsed.selectedJwkIndex : 0;
	setJWKSStatus(`Valid JWKS. Selected keys[${selectedIndex}] kty=${selectedKty}, kid=${selectedKid}, alg=${selectedAlg}.`, 'success', true);
}

function applyReadOnlyJwkMode(key: any, mode: 'url' | 'jwks-json'): void {
	keyNameInput.disabled = false;
	setPublicKeyReadOnlyMode(true);
	publicKeySection.style.display = 'none';
	saveBtn.style.display = 'inline-block';
	saveBtn.textContent = 'Save Changes';
	manualMetadataSection.style.display = 'block';
	rawJsonSection.style.display = 'block';
	lastFetchedItem.style.display = 'none';
	nextRefreshItem.style.display = 'none';

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
	rawJsonToggle.textContent = getRawJsonShowLabel();

	if (mode === 'url') {
		refreshBtn.style.display = 'inline-block';
		urlSection.style.display = 'block';
		keyUrlReadonly.textContent = key.url || '';
		keyUrlReadonly.style.display = 'block';
		keyUrlInput.style.display = 'none';
		urlHelp.style.display = 'none';

		refreshSection.style.display = 'block';
		refreshPeriodReadonly.style.display = 'none';
		refreshPeriodSelect.style.display = 'block';
		refreshPeriodSelect.value = key.refreshPeriod || 'weekly';
		jwksJsonSection.style.display = 'none';
		jwksJsonInput.disabled = false;
		setJWKSStatus('', 'info', false);

		if (key.lastFetchedAt) {
			lastFetchedItem.style.display = 'block';
			lastFetchedSpan.textContent = formatDateTime(key.lastFetchedAt);
		}

		if (key.nextRefreshAt) {
			nextRefreshItem.style.display = 'block';
			nextRefreshSpan.textContent = formatDateTime(key.nextRefreshAt);
		}
		return;
	}

	refreshBtn.style.display = 'none';
	urlSection.style.display = 'none';
	refreshSection.style.display = 'none';
	jwksJsonSection.style.display = 'block';
	jwksJsonInput.disabled = false;
	autoResizeTextarea(jwksJsonInput);
	setJWKSStatus('Edit JWKS JSON and save to update this key set.', 'info', true);
}

// Safe initial UI state until extension sends createMode/keyData.
refreshBtn.style.display = 'none';
deleteBtn.style.display = 'none';
rawJsonSection.style.display = 'none';
updateDescriptionCounter();

// Event Listeners
sourceUrlRadio.addEventListener('change', updateFormBasedOnSource);
sourceJwksJsonRadio.addEventListener('change', updateFormBasedOnSource);
sourceManualRadio.addEventListener('change', updateFormBasedOnSource);
keyDescriptionInput.addEventListener('input', () => {
	updateDescriptionCounter();
});
keyDataTextarea.addEventListener('input', () => {
	void updateDerivedModulusClaim();
	updateManualRawJsonPreview();
});
jwksJsonInput.addEventListener('input', () => {
	if (sourceJwksJsonRadio.checked) {
		updateJWKSPreviewFromInput();
	}
});

claimsFields.addEventListener('input', (event) => {
	const target = event.target as HTMLInputElement;
	if (!target || !target.dataset.claimKey) {
		return;
	}
	currentClaims[target.dataset.claimKey] = target.value;
	if (target.dataset.claimKey === 'e') {
		renderExponentHint(target);
	}
	updateManualRawJsonPreview();
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
	rawJsonToggle.textContent = visible ? getRawJsonShowLabel() : getRawJsonHideLabel();
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

function getValidatedDescription(): { valid: boolean; value?: string; error?: string } {
	const value = keyDescriptionInput.value.trim();
	if (value.length > 50) {
		return { valid: false, error: 'Description must be 50 characters or fewer' };
	}
	return { valid: true, value };
}

function updateDescriptionCounter(): void {
	keyDescriptionCounter.textContent = `${keyDescriptionInput.value.length}/50`;
}

function updateFormBasedOnSource(): void {
	const isUrl = sourceUrlRadio.checked;
	const isJwksJson = sourceJwksJsonRadio.checked;
	
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
		setPublicKeyReadOnlyMode(true);
		keyDataTextarea.placeholder = 'Key will be fetched from URL';
		publicKeySection.style.display = 'none';
		jwksJsonSection.style.display = 'none';
		setJWKSStatus('', 'info', false);
		manualMetadataSection.style.display = isCreateMode ? 'none' : 'block';
		keySelectionSection.style.display = 'none';
		rawJsonSection.style.display = 'none';
	} else if (isJwksJson) {
		urlSection.style.display = 'none';
		urlHelp.style.display = 'none';
		refreshSection.style.display = 'none';

		jwksJsonSection.style.display = 'block';
		jwksJsonInput.disabled = false;
		autoResizeTextarea(jwksJsonInput);

		setPublicKeyReadOnlyMode(true);
		keyDataTextarea.placeholder = 'Public key is derived from the selected JWKS key';
		publicKeySection.style.display = 'none';
		manualMetadataSection.style.display = 'block';
		keySelectionSection.style.display = 'none';
		rawJsonSection.style.display = isCreateMode ? 'none' : 'block';
		updateJWKSPreviewFromInput();
	} else {
		// Hide URL fields
		urlSection.style.display = 'none';
		urlHelp.style.display = 'none';
		refreshSection.style.display = 'none';
		jwksJsonSection.style.display = 'none';
		
		// Enable key data textarea
		setPublicKeyReadOnlyMode(false);
		keyDataTextarea.placeholder = 'Paste PEM-encoded public key here';
		publicKeySection.style.display = 'block';
		manualMetadataSection.style.display = 'block';
		keySelectionSection.style.display = 'none';
		setJWKSStatus('', 'info', false);
		ensureManualClaimDefaults(currentClaims);
		renderClaims(currentClaims, false);
		void updateDerivedModulusClaim();
		updateManualRawJsonPreview();
	}
}

function handleCreateKey(): void {
	const name = keyNameInput.value.trim();
	const description = getValidatedDescription();
	ensureManualClaimDefaults(currentClaims);
	const algorithm = (typeof currentClaims.alg === 'string' && currentClaims.alg.trim()) ? currentClaims.alg.trim() : 'RS256';
	const keyType = (typeof currentClaims.kty === 'string' && currentClaims.kty.trim()) ? currentClaims.kty.trim() : 'RSA';
	
	if (!name) {
		showError('Key name is required');
		return;
	}

	if (!description.valid) {
		showError(description.error || 'Invalid description');
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
			description: description.value,
			url,
			refreshPeriod
		});
	} else if (sourceJwksJsonRadio.checked) {
		const parsedJwks = parseJWKSInput(jwksJsonInput.value);
		if (!parsedJwks.valid || !parsedJwks.normalizedJson) {
			showError(parsedJwks.error || 'Invalid JWKS JSON input');
			return;
		}

		vscodeApi.postMessage({
			type: 'createJWKSJsonKey',
			name,
			description: description.value,
			jwksJson: parsedJwks.normalizedJson
		});
	} else {
		// Create manual key
		const validation = validateManualPemInput(keyDataTextarea.value);
		if (!validation.valid) {
			showError(validation.error || 'Invalid public key');
			return;
		}

		const claimsValidation = validateManualClaims(currentClaims);
		if (!claimsValidation.valid) {
			showError(claimsValidation.error || 'Invalid manual key claims');
			return;
		}
		
		vscodeApi.postMessage({
			type: 'createManualKey',
			name,
			description: description.value,
			keyData: validation.normalized,
			algorithm,
			keyType,
			claims: currentClaims
		});
	}
}

function handleUpdateKey(): void {
	const name = keyNameInput.value.trim();
	const description = getValidatedDescription();
	ensureManualClaimDefaults(currentClaims);
	const algorithm = (typeof currentClaims.alg === 'string' && currentClaims.alg.trim()) ? currentClaims.alg.trim() : 'RS256';
	const keyType = (typeof currentClaims.kty === 'string' && currentClaims.kty.trim()) ? currentClaims.kty.trim() : 'RSA';

	if (!name) {
		showError('Key name is required');
		return;
	}

	if (!description.valid) {
		showError(description.error || 'Invalid description');
		return;
	}

	if (!isUrlKey && !isJwksJsonKey) {
		const validation = validateManualPemInput(keyDataTextarea.value);
		if (!validation.valid) {
			showError(validation.error || 'Invalid public key');
			return;
		}

		const claimsValidation = validateManualClaims(currentClaims);
		if (!claimsValidation.valid) {
			showError(claimsValidation.error || 'Invalid manual key claims');
			return;
		}

		vscodeApi.postMessage({
			type: 'updateKey',
			name,
			description: description.value,
			keyData: validation.normalized,
			algorithm,
			keyType,
			claims: currentClaims
		});
		return;
	}

	if (isJwksJsonKey) {
		const parsedJwks = parseJWKSInput(jwksJsonInput.value);
		if (!parsedJwks.valid || !parsedJwks.normalizedJson) {
			showError(parsedJwks.error || 'Invalid JWKS JSON input');
			return;
		}

		vscodeApi.postMessage({
			type: 'updateKey',
			name,
			description: description.value,
			keyData: keyDataTextarea.value,
			algorithm,
			jwksJson: parsedJwks.normalizedJson
		});
		return;
	}

	vscodeApi.postMessage({
		type: 'updateKey',
		name,
		description: description.value,
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
	isJwksJsonKey = false;
	currentClaims = { ...DEFAULT_MANUAL_CLAIMS };
	
	// Update title and UI for create mode
	keyTitle.textContent = 'Add New Validation Key';
	keySource.style.display = 'none';
	keyDescriptionInput.value = '';
	updateDescriptionCounter();
	
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
	rawJsonToggle.textContent = getRawJsonShowLabel();
	
	// Update save button text
	saveBtn.textContent = 'Add Key';
	refreshBtn.style.display = 'none';
	
	// Hide delete button (nothing to delete yet)
	deleteBtn.style.display = 'none';

	// Default new entry to Manual source for clearer UX.
	sourceManualRadio.checked = true;
	sourceUrlRadio.checked = false;
	sourceJwksJsonRadio.checked = false;
	jwksJsonInput.value = '';
	autoResizeTextarea(jwksJsonInput);
	setJWKSStatus('', 'info', false);
	keySelectionSection.style.display = 'none';
	rawJsonSection.style.display = 'block';
	renderClaims(currentClaims, false);
	void updateDerivedModulusClaim();
	updateManualRawJsonPreview();
	
	// Initialize form state
	updateFormBasedOnSource();
}

function renderClaims(claims: Record<string, unknown> | undefined, readOnly: boolean): void {
	claimsFields.classList.remove('key-groups');
	if (!claims || Object.keys(claims).length === 0) {
		claimsFields.innerHTML = '';
		return;
	}

	claimsFields.innerHTML = Object.entries(claims).map(([key, value]) => {
		const commonName = CLAIM_NAME_DICTIONARY[key] || key.toUpperCase();
		const label = `${commonName} (${key})`;
		let displayValue = '';
		let editable = !readOnly && !NON_EDITABLE_MANUAL_CLAIMS.has(key);
		if (key === 'n') {
			displayValue = typeof value === 'string' ? value : '';
		} else if (typeof value === 'string') {
			displayValue = value;
		} else {
			displayValue = JSON.stringify(value);
			editable = false;
		}

		const valueHtml = editable
			? `<input class="input" data-claim-key="${escapeHtml(key)}" value="${escapeHtml(displayValue)}" />`
			: `<div class="readonly-field claim-readonly">${escapeHtml(displayValue)}</div>`;
		const helpHtml = key === 'e'
			? '<div class="claim-hint">AQAB is Base64URL for exponent 65537 (common RSA public exponent).</div>'
			: key === 'n'
				? '<div class="claim-hint">Managed by the Public Key PEM field and shown here as read-only.</div>'
				: '';
		return `
			<div class="metadata-item">
				<span class="metadata-label">${escapeHtml(label)}:</span>
				${valueHtml}
				${helpHtml}
			</div>
		`;
	}).join('');

	if (!readOnly) {
		const exponentInput = claimsFields.querySelector('input[data-claim-key="e"]') as HTMLInputElement | null;
		if (exponentInput) {
			renderExponentHint(exponentInput);
		}
	}
}

function getClaimFieldHtml(claimKey: string, value: unknown, readOnly: boolean): string {
	const commonName = CLAIM_NAME_DICTIONARY[claimKey] || claimKey.toUpperCase();
	const label = `${commonName} (${claimKey})`;
	let displayValue = '';
	let editable = !readOnly && !NON_EDITABLE_MANUAL_CLAIMS.has(claimKey);
	if (claimKey === 'n') {
		displayValue = typeof value === 'string' ? value : '';
	} else if (typeof value === 'string') {
		displayValue = value;
	} else {
		displayValue = JSON.stringify(value);
		editable = false;
	}

	const valueHtml = editable
		? `<input class="input" data-claim-key="${escapeHtml(claimKey)}" value="${escapeHtml(displayValue)}" />`
		: `<div class="readonly-field claim-readonly">${escapeHtml(displayValue)}</div>`;
	const helpHtml = claimKey === 'e'
		? '<div class="claim-hint">AQAB is Base64URL for exponent 65537 (common RSA public exponent).</div>'
		: claimKey === 'n'
			? '<div class="claim-hint">Managed by the Public Key PEM field and shown here as read-only.</div>'
			: '';

	return `
		<div class="metadata-item">
			<span class="metadata-label">${escapeHtml(label)}:</span>
			${valueHtml}
			${helpHtml}
		</div>
	`;
}

function renderGroupedKeyClaims(keys: Record<string, unknown>[]): void {
	claimsFields.classList.add('key-groups');
	if (!keys.length) {
		claimsFields.innerHTML = '<p class="hint">No keys found in JWKS.</p>';
		return;
	}

	claimsFields.innerHTML = keys.map((jwk, index) => {
		const kid = typeof jwk.kid === 'string' && jwk.kid.trim() ? jwk.kid.trim() : '(none)';
		const kty = typeof jwk.kty === 'string' && jwk.kty.trim() ? jwk.kty.trim() : '(unknown)';
		const groupTitle = `Key ${index + 1} - kty=${kty}, kid=${kid}`;
		const claimItems = Object.entries(jwk)
			.map(([claimKey, value]) => getClaimFieldHtml(claimKey, value, true))
			.join('');

		return `
			<div class="key-claims-group">
				<div class="key-claims-title">${escapeHtml(groupTitle)}</div>
				<div class="metadata-grid">${claimItems}</div>
				<div class="metadata-item grouped-public-key-item">
					<span class="metadata-label">Public Key:</span>
					<pre
						class="readonly-field grouped-public-key"
						data-group-public-key-index="${index}"
					>Deriving from JWK...</pre>
				</div>
			</div>
		`;
	}).join('');

	void populateGroupedPublicKeys(keys);
}

function extractKeySetFromRawJson(rawJson: unknown): Record<string, unknown>[] {
	if (typeof rawJson !== 'string' || !rawJson.trim()) {
		return [];
	}
	try {
		const parsed = JSON.parse(rawJson);
		if (!isRecord(parsed) || !Array.isArray(parsed.keys)) {
			return [];
		}
		return parsed.keys.filter(isRecord);
	} catch {
		return [];
	}
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
	isJwksJsonKey = key.source === 'jwks-json';
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
	sourceJwksJsonRadio.checked = isJwksJsonKey;
	sourceManualRadio.checked = !isUrlKey && !isJwksJsonKey;

	// Update form
	keyNameInput.value = key.name;
	keyDescriptionInput.value = typeof key.description === 'string' ? key.description : '';
	updateDescriptionCounter();
	keyDataTextarea.value = key.keyData || '';
	keyDataReadonly.textContent = keyDataTextarea.value || 'Public key is managed by this source.';
	jwksJsonInput.value = typeof key.jwksJson === 'string' ? key.jwksJson : '';
	autoResizeTextarea(jwksJsonInput);
	publicKeySection.style.display = 'block';
	currentClaims = (key.claims && typeof key.claims === 'object') ? { ...key.claims } : {};
	renderPreferredKeyOptions();
	if (isUrlKey || isJwksJsonKey) {
		const keySet = extractKeySetFromRawJson(key.rawJson);
		if (keySet.length > 0) {
			renderGroupedKeyClaims(keySet);
		} else {
			renderClaims(currentClaims, true);
		}
	} else {
		renderClaims(currentClaims, false);
	}

	// Disable editing for URL keys
	if (isUrlKey) {
		applyReadOnlyJwkMode(key, 'url');
	} else if (isJwksJsonKey) {
		applyReadOnlyJwkMode(key, 'jwks-json');
	} else {
		keyNameInput.disabled = false;
		setPublicKeyReadOnlyMode(false);
		jwksJsonInput.disabled = false;
		renderPreferredKeyOptions();
		ensureManualClaimDefaults(currentClaims);
		renderClaims(currentClaims, false);
		void updateDerivedModulusClaim();
		updateManualRawJsonPreview();
		saveBtn.style.display = 'inline-block';
		saveBtn.textContent = 'Save Changes';
		refreshBtn.style.display = 'none';

		urlSection.style.display = 'none';
		refreshSection.style.display = 'none';
		jwksJsonSection.style.display = 'none';
		manualMetadataSection.style.display = 'block';
		rawJsonSection.style.display = 'block';
		rawJsonContent.style.display = 'none';
		rawJsonToggle.textContent = getRawJsonShowLabel();
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
