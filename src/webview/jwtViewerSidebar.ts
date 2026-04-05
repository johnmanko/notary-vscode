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

// Webview script for the JWT viewer sidebar.
// Compiled by esbuild to media/jwtViewerSidebar.js — runs in the webview (browser) context.
import { escapeHtml } from './utils';

declare function acquireVsCodeApi(): {
	postMessage(message: unknown): void;
};

interface PanelInfo {
	id: string;
	label: string;
	createdAt: string;
}

interface ValidationKey {
	id: string;
	name: string;
	description?: string;
	source: 'manual' | 'url' | 'jwks-json';
	url?: string;
	refreshPeriod?: string;
	lastFetchedAt?: number;
	nextRefreshAt?: number;
}

const vscodeApi = acquireVsCodeApi();

// Panel management
document.getElementById('new-btn')!.addEventListener('click', () => {
	vscodeApi.postMessage({ type: 'newPanel' });
});

// Key management - Add new key button
const addKeyBtn = document.getElementById('add-key-btn') as HTMLButtonElement;
addKeyBtn.addEventListener('click', () => {
	vscodeApi.postMessage({ type: 'addNewKey' });
});

// Message handling
window.addEventListener('message', (event: MessageEvent<{
	type: string;
	panels?: PanelInfo[];
	keys?: ValidationKey[];
	error?: string;
}>) => {
	const data = event.data;
	
	if (data.type === 'panelList') {
		renderList(data.panels || []);
	} else if (data.type === 'keyList') {
		renderKeyList(data.keys || []);
	} else if (data.type === 'keyError' && data.error) {
		// Errors are now shown in the key details panel or as VS Code notifications
		console.error('Key error:', data.error);
	}
});

function formatTime(iso: string): string {
	try {
		return new Date(iso).toLocaleTimeString([], {
			hour: '2-digit', minute: '2-digit', second: '2-digit'
		});
	} catch (_) { return iso; }
}

function formatTimestamp(ts: number): string {
	try {
		return new Date(ts).toLocaleString([], {
			month: 'short',
			day: 'numeric',
			hour: '2-digit',
			minute: '2-digit'
		});
	} catch (_) { return ts.toString(); }
}

function renderList(panels: PanelInfo[]): void {
	const container = document.getElementById('panel-list')!;
	if (!panels || panels.length === 0) {
		container.innerHTML = '<div class="empty">No open viewers.<br>Click above to start one.</div>';
		return;
	}
	container.innerHTML = panels.map(p =>
		`<div class="panel-item" data-id="${escapeHtml(p.id)}">` +
			`<div class="pi-name" title="${escapeHtml(p.label)}">${escapeHtml(p.label)}</div>` +
			`<div class="pi-time">Created ${escapeHtml(formatTime(p.createdAt))}</div>` +
		`</div>`
	).join('');

	container.querySelectorAll<HTMLElement>('.panel-item').forEach(el => {
		el.addEventListener('click', () => {
			vscodeApi.postMessage({ type: 'activatePanel', id: el.getAttribute('data-id') });
		});
	});
}

function renderKeyList(keys: ValidationKey[]): void {
	const container = document.getElementById('key-list')!;
	if (!keys || keys.length === 0) {
		container.innerHTML = '<div class="empty">No validation keys.<br>Add one above to get started.</div>';
		return;
	}

	container.innerHTML = keys.map(key => {
		const isUrl = key.source === 'url';
		const badge = `<span class="key-badge ${key.source}">${escapeHtml(key.source.toUpperCase())}</span>`;
		const description = typeof key.description === 'string' && key.description.trim()
			? `<div class="key-description">${escapeHtml(key.description.trim())}</div>`
			: '';
		
		let details = '';
		if (isUrl && key.url) {
			const lastFetch = key.lastFetchedAt ? formatTimestamp(key.lastFetchedAt) : 'Never';
			const nextFetch = key.nextRefreshAt ? formatTimestamp(key.nextRefreshAt) : 'Unknown';
			details = `
				<div class="key-url">URL: ${escapeHtml(key.url)}</div>
				<div class="key-times">
					Last: ${escapeHtml(lastFetch)} | Next: ${escapeHtml(nextFetch)}
				</div>
			`;
		}

		const actions = isUrl
			? `<button class="key-action-btn" data-action="refresh" data-id="${escapeHtml(key.id)}">Refresh</button>`
			: '';

		return `
			<div class="key-item">
				<div class="key-header">
					<div class="key-name">${escapeHtml(key.name)}</div>
					${badge}
				</div>
				${description}
				<div class="key-details">
					${details}
				</div>
				<div class="key-actions">
					<button class="key-action-btn" data-action="view" data-id="${escapeHtml(key.id)}">View Key</button>
					${actions}
					<button class="key-action-btn danger" data-action="delete" data-id="${escapeHtml(key.id)}">Delete</button>
				</div>
			</div>
		`;
	}).join('');

	// Attach event listeners
	container.querySelectorAll<HTMLButtonElement>('.key-action-btn').forEach(btn => {
		btn.addEventListener('click', () => {
			const action = btn.getAttribute('data-action');
			const id = btn.getAttribute('data-id');
			
			if (action === 'delete') {
				vscodeApi.postMessage({ type: 'deleteKey', id });
			} else if (action === 'refresh') {
				vscodeApi.postMessage({ type: 'refreshKey', id });
			} else if (action === 'view') {
				vscodeApi.postMessage({ type: 'viewKey', id });
			}
		});
	});
}
