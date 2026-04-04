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

// Webview script for the JWT viewer editor panel.
// Compiled by esbuild to media/jwtViewerPanel.js — runs in the webview (browser) context.
import { escapeHtml } from './utils';
import { decodeJwt as parseJwt, isTokenExpired, getTimestampFields } from './utils/jwtUtils';

declare function acquireVsCodeApi(): {
	postMessage(message: unknown): void;
};

const vscodeApi = acquireVsCodeApi();

const jwtInput       = document.getElementById('jwt-input')       as HTMLElement;
const errorBanner    = document.getElementById('error-banner')    as HTMLElement;
const errorText      = document.getElementById('error-text')      as HTMLElement;
const headerContent  = document.getElementById('header-content')  as HTMLElement;
const payloadContent = document.getElementById('payload-content') as HTMLElement;
const sigContent     = document.getElementById('sig-content')     as HTMLElement;
const expiryBadge    = document.getElementById('expiry-badge')    as HTMLElement;
const tsTable        = document.getElementById('ts-table')        as HTMLElement;
const keySelect      = document.getElementById('key-select')      as HTMLSelectElement;
const validateBtn    = document.getElementById('validate-btn')    as HTMLButtonElement;
const validationStatus = document.getElementById('validation-status') as HTMLElement;
const validationResult = document.getElementById('validation-result') as HTMLElement;

let currentToken = '';

interface ValidationKey {
	id: string;
	name: string;
	source: 'manual' | 'url';
}

function moveCursorToEnd(): void {
	const range = document.createRange();
	const sel = window.getSelection();
	if (!sel) { return; }
	range.selectNodeContents(jwtInput);
	range.collapse(false);
	sel.removeAllRanges();
	sel.addRange(range);
}

function getRawToken(): string {
	return (jwtInput.innerText ?? '').replaceAll(/\s/g, '');
}

function highlight(json: string): string {
	// Match tokens on the RAW string first, then escape each piece individually.
	// (Escaping the whole string first would turn " into &quot; and break all string/key matches.)
	const re = /("(?:\\u[0-9a-fA-F]{4}|\\[^u]|[^\\"])*"(?:\s*:)?|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?|\b(?:true|false|null)\b|[{}[\]:,])/g;
	let out = '';
	let last = 0;
	let m: RegExpExecArray | null;
	while ((m = re.exec(json)) !== null) {
		out += escapeHtml(json.slice(last, m.index));
		const tok = m[0];
		let cls: string;
		if (tok.startsWith('"'))              { cls = /:\s*$/.test(tok) ? 'jk' : 'js'; }
		else if (tok === 'true' || tok === 'false') { cls = 'jb'; }
		else if (tok === 'null')              { cls = 'jnull'; }
		else if (/^[{}\[\]]$/.test(tok))     { cls = 'jp-brace'; }
		else if (tok === ':')                 { cls = 'jp-colon'; }
		else if (tok === ',')                 { cls = 'jp-comma'; }
		else                                  { cls = 'jn'; }
		out += `<span class="${cls}">${escapeHtml(tok)}</span>`;
		last = m.index + tok.length;
	}
	out += escapeHtml(json.slice(last));
	return out;
}

function fmtTime(unix: number): string {
	return new Date(unix * 1000).toISOString().replaceAll('T', ' ').replaceAll('Z', ' UTC');
}

function showError(msg: string): void {
	errorText.textContent = msg;
	errorBanner.classList.add('visible');
	jwtInput.classList.add('has-error');
}
function clearError(): void {
	errorBanner.classList.remove('visible');
	jwtInput.classList.remove('has-error');
}

function setPlaceholder(el: HTMLElement, text: string): void {
	el.classList.add('placeholder');
	el.textContent = text;
}
function setContent(el: HTMLElement, html: string): void {
	el.classList.remove('placeholder');
	el.innerHTML = html;
}

function resetSections(text: string): void {
	setPlaceholder(headerContent, text);
	setPlaceholder(payloadContent, text);
	setPlaceholder(sigContent, text);
	expiryBadge.className = 'expiry-badge';
	tsTable.className = 'ts-table hidden';
	tsTable.innerHTML = '';
}

function decodeJwt(raw: string): void {
	const token = (raw ?? '').trim();
	currentToken = token;
	vscodeApi.postMessage({ type: 'jwtChanged', encoded: token });
	
	// Update validate button state
	validateBtn.disabled = !token || keySelect.value === '';
	
	if (!token) {
		clearError();
		resetSections('Awaiting token\u2026');
		clearValidation();
		return;
	}

	// Use the JWT utility to parse the token
	const result = parseJwt(token);
	
	if (!result.success) {
		showError(result.error);
		resetSections('\u2014');
		clearValidation();
		if (jwtInput.children.length > 0) {
			jwtInput.textContent = token;
			moveCursorToEnd();
		}
		return;
	}
	
	const { header, payload, parts } = result;

	clearError();

	jwtInput.innerHTML =
		`<span class="c-header">${escapeHtml(parts[0])}</span>` +
		`<span class="c-dot">.</span>` +
		`<span class="c-payload">${escapeHtml(parts[1])}</span>` +
		`<span class="c-dot">.</span>` +
		`<span class="c-sig">${escapeHtml(parts[2])}</span>`;
	moveCursorToEnd();

	setContent(headerContent,  highlight(JSON.stringify(header, null, 2)));
	setContent(payloadContent, highlight(JSON.stringify(payload, null, 2)));

	// Use utility to get timestamp fields
	const tsFields = getTimestampFields(payload);
	if (tsFields.length > 0) {
		const labels: Record<string, string> = { iat: 'Issued at', nbf: 'Not before', exp: 'Expires' };
		tsTable.innerHTML = tsFields.map(k =>
			`<div class="ts-row">` +
			`<span class="ts-key">${k}</span>` +
			`<span class="ts-val"><span class="ts-label">${escapeHtml(labels[k])}</span> &nbsp;${escapeHtml(fmtTime(payload[k] as number))}</span>` +
			`</div>`
		).join('');
		tsTable.className = 'ts-table';
	} else {
		tsTable.className = 'ts-table hidden';
	}

	// Use utility to check expiration
	if (typeof payload.exp === 'number') {
		if (isTokenExpired(payload)) {
			expiryBadge.textContent = 'Expired';
			expiryBadge.className = 'expiry-badge expired';
		} else {
			expiryBadge.textContent = 'Valid';
			expiryBadge.className = 'expiry-badge valid';
		}
	} else {
		expiryBadge.className = 'expiry-badge';
	}

	const b = `<span class="jp-brace">`;
	const eb = `</span>`;
	const col = `<span class="jp-colon">:</span>`;
	const com = `<span class="jp-comma">,</span>`;
	const algLine = header.alg
		? `  <span class="jk">"alg"</span>${col} <span class="js">"${escapeHtml(String(header.alg))}"</span>${com}\n`
		: '';
	setContent(sigContent,
		`${b}{${eb}\n` +
		algLine +
		`  <span class="jk">"value"</span>${col} <span class="c-sig">"${escapeHtml(parts[2])}"</span>\n` +
		`${b}}${eb}`
	);
}

document.getElementById('clear-btn')!.addEventListener('click', () => {
	jwtInput.textContent = '';
	decodeJwt('');
});

jwtInput.addEventListener('keydown', (e: KeyboardEvent) => {
	if (e.key === 'Enter') { e.preventDefault(); }
});
jwtInput.addEventListener('input', () => decodeJwt(getRawToken()));
jwtInput.addEventListener('paste', (e: ClipboardEvent) => {
	e.preventDefault();
	const text = (e.clipboardData?.getData('text/plain') ?? '').replaceAll(/\s/g, '');
	jwtInput.textContent = text;
	decodeJwt(text);
});

document.querySelectorAll<HTMLButtonElement>('.copy-btn').forEach(btn => {
	btn.addEventListener('click', () => {
		const targetId = btn.getAttribute('data-target');
		if (!targetId) { return; }
		const el = document.getElementById(targetId);
		if (!el || el.classList.contains('placeholder')) { return; }
		navigator.clipboard.writeText(el.innerText).then(() => {
			btn.textContent = 'Copied!';
			btn.classList.add('copied');
			setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1500);
		});
	});
});

// ── Validation functionality ──

function clearValidation(): void {
	validationStatus.className = 'validation-status';
	validationResult.className = 'validation-result hidden';
	validationResult.textContent = '';
}

function showValidationResult(isValid: boolean, message: string): void {
	validationResult.className = `validation-result ${isValid ? 'valid' : 'invalid'}`;
	const icon = isValid ? '✓' : '✗';
	validationResult.innerHTML = `<span class="result-icon">${icon}</span>${escapeHtml(message)}`;
	
	validationStatus.className = `validation-status ${isValid ? 'valid' : 'invalid'}`;
	validationStatus.textContent = isValid ? 'Valid' : 'Invalid';
}

// Key selection change
keySelect.addEventListener('change', () => {
	validateBtn.disabled = !currentToken || keySelect.value === '';
	clearValidation();
});

// Validate button click
validateBtn.addEventListener('click', () => {
	const keyId = keySelect.value;
	if (!keyId || !currentToken) {
		return;
	}
	
	clearValidation();
	vscodeApi.postMessage({
		type: 'validateSignature',
		keyId,
		token: currentToken
	});
});

// Handle messages from extension
window.addEventListener('message', (event: MessageEvent<{
	type: string;
	keys?: ValidationKey[];
	isValid?: boolean;
	message?: string;
}>) => {
	const data = event.data;
	
	if (data.type === 'keyList') {
		updateKeyList(data.keys || []);
	} else if (data.type === 'validationResult') {
		showValidationResult(data.isValid ?? false, data.message || '');
	}
});

function updateKeyList(keys: ValidationKey[]): void {
	const currentValue = keySelect.value;
	
	// Clear and rebuild options
	keySelect.innerHTML = '<option value="">Select a validation key...</option>';
	
	keys.forEach(key => {
		const option = document.createElement('option');
		option.value = key.id;
		option.textContent = `${key.name} (${key.source})`;
		keySelect.appendChild(option);
	});
	
	// Restore previous selection if still available
	if (currentValue && keys.some(k => k.id === currentValue)) {
		keySelect.value = currentValue;
	}
	
	// Update validate button state
	validateBtn.disabled = !currentToken || keySelect.value === '';
}

// Request initial key list
vscodeApi.postMessage({ type: 'requestKeyList' });
