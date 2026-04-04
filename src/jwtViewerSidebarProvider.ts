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
import { loadHtmlTemplate, createAssetUris, getMediaRootUri } from './utils/webviewUtils';
import { KeyManager } from './utils/keyManager';
import { RefreshPeriod } from './types/keyManagement';
import { KeyDetailsPanel } from './keyDetailsPanel';
import { confirmAndDeleteKey } from './utils/keyDeletion';

export interface PanelInfo {
	id: string;
	label: string;
	createdAt: string;
}

export class JwtViewerSidebarProvider implements vscode.WebviewViewProvider {
	public static readonly viewId = 'notary.sidebarView';
	private _view?: vscode.WebviewView;
	private readonly keyManager: KeyManager;
	private onKeyChange?: () => Promise<void>;

	constructor(
		private readonly _extensionUri: vscode.Uri,
		context: vscode.ExtensionContext,
		private readonly _onNewPanel: () => void,
		private readonly _onActivatePanel: (id: string) => void
	) {
		this.keyManager = new KeyManager(context);
	}

	public setKeyChangeCallback(callback: () => Promise<void>): void {
		this.onKeyChange = callback;
	}

	private async notifyKeyChange(): Promise<void> {
		await this.updateKeyList();
		if (this.onKeyChange) {
			await this.onKeyChange();
		}
	}

	resolveWebviewView(
		webviewView: vscode.WebviewView,
		_context: vscode.WebviewViewResolveContext,
		_token: vscode.CancellationToken
	): void {
		this._view = webviewView;
		webviewView.webview.options = { enableScripts: true, localResourceRoots: [getMediaRootUri(this._extensionUri)] };
		webviewView.webview.html = this._getHtmlContent(webviewView.webview);
		
		// Handle messages from webview
		webviewView.webview.onDidReceiveMessage(async (message) => {
			if (message.type === 'newPanel') {
				this._onNewPanel();
			} else if (message.type === 'activatePanel') {
				this._onActivatePanel(message.id as string);
			} else if (message.type === 'addNewKey') {
				await this.handleAddNewKey();
			} else if (message.type === 'addManualKey') {
				await this.handleAddManualKey(message.name, message.publicKey);
			} else if (message.type === 'addURLKey') {
				await this.handleAddURLKey(message.name, message.url, message.refreshPeriod);
			} else if (message.type === 'deleteKey') {
				await this.handleDeleteKey(message.id);
			} else if (message.type === 'refreshKey') {
				await this.handleRefreshKey(message.id);
			} else if (message.type === 'viewKey') {
				await this.handleViewKey(message.id);
			}
		});

		// Initial load of keys
		this.updateKeyList();
	}

	private async handleAddNewKey() {
		KeyDetailsPanel.createOrShow(
			this._extensionUri,
			null, // null indicates create mode
			this.keyManager,
			async () => {
				await this.notifyKeyChange();
			}
		);
	}

	private async handleAddManualKey(name: string, publicKey: string) {
		const result = await this.keyManager.addManualKey(name, publicKey);
		if (result.success) {
			vscode.window.showInformationMessage(`Key "${name}" added successfully`);
			await this.notifyKeyChange();
		} else {
			this.showKeyError(result.error || 'Failed to add key');
		}
	}

	private async handleAddURLKey(name: string, url: string, refreshPeriod: string) {
		// Show progress
		await vscode.window.withProgress({
			location: vscode.ProgressLocation.Notification,
			title: `Fetching key from ${url}...`,
			cancellable: false
		}, async () => {
			const period = refreshPeriod as RefreshPeriod;
			const result = await this.keyManager.addURLKey(name, url, period);
			
			if (result.success) {
				vscode.window.showInformationMessage(`Key "${name}" fetched and added successfully`);
				await this.notifyKeyChange();
			} else {
				this.showKeyError(result.error || 'Failed to fetch key from URL');
			}
		});
	}

	private async handleDeleteKey(id: string) {
		await confirmAndDeleteKey(this.keyManager, id, async () => {
			KeyDetailsPanel.closeIfShowingKey(id);
			await this.notifyKeyChange();
		});
	}

	private async handleRefreshKey(id: string) {
		await vscode.window.withProgress({
			location: vscode.ProgressLocation.Notification,
			title: 'Refreshing key...',
			cancellable: false
		}, async () => {
			const result = await this.keyManager.refreshURLKey(id);
			
			if (result.success) {
				vscode.window.showInformationMessage('Key refreshed successfully');
				await this.notifyKeyChange();
			} else {
				vscode.window.showErrorMessage(result.error || 'Failed to refresh key');
			}
		});
	}

	private async handleViewKey(id: string) {
		const key = await this.keyManager.getKeyById(id);
		if (!key) {
			vscode.window.showErrorMessage('Key not found');
			return;
		}

		KeyDetailsPanel.createOrShow(
			this._extensionUri,
			id,
			this.keyManager,
			async () => {
				await this.notifyKeyChange();
			}
		);
	}

	private showKeyError(error: string) {
		if (this._view) {
			this._view.webview.postMessage({ type: 'keyError', error });
		}
		vscode.window.showErrorMessage(error);
	}

	public updatePanelList(panels: PanelInfo[]): void {
		if (this._view) {
			this._view.webview.postMessage({ type: 'panelList', panels });
		}
	}

	public async updateKeyList(): Promise<void> {
		if (this._view) {
			const keys = await this.keyManager.getAllKeys();
			// Convert to a format suitable for the webview
			const serializedKeys = keys.map(key => ({
				id: key.id,
				name: key.name,
				source: key.source,
				url: 'url' in key ? key.url : undefined,
				refreshPeriod: 'refreshPeriod' in key ? key.refreshPeriod : undefined,
				lastFetchedAt: 'lastFetchedAt' in key ? key.lastFetchedAt : undefined,
				nextRefreshAt: 'nextRefreshAt' in key ? key.nextRefreshAt : undefined
			}));
			this._view.webview.postMessage({ type: 'keyList', keys: serializedKeys });
		}
	}

	public getKeyManager(): KeyManager {
		return this.keyManager;
	}

	private _getHtmlContent(webview: vscode.Webview): string {
		const assetUris = createAssetUris(this._extensionUri, webview, 'jwtViewerSidebar');
		return loadHtmlTemplate(this._extensionUri, webview, 'jwtViewerSidebar.html', assetUris);
	}
}