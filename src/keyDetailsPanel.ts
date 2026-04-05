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
import { KeyManager } from './utils/keyManager';
import { isURLKey, isJWKSJsonKey, RefreshPeriod } from './types/keyManagement';
import { loadHtmlTemplate, createAssetUris, getMediaRootUri } from './utils/webviewUtils';
import { confirmAndDeleteKey } from './utils/keyDeletion';

export class KeyDetailsPanel {
	public static currentPanel: KeyDetailsPanel | undefined;

	public static closeIfShowingKey(keyId: string): void {
		const panel = KeyDetailsPanel.currentPanel;
		if (!panel) {
			return;
		}
		if (panel._keyId !== keyId) {
			return;
		}
		panel.dispose();
	}

	private readonly _panel: vscode.WebviewPanel;
	private readonly _extensionUri: vscode.Uri;
	private _disposables: vscode.Disposable[] = [];
	private readonly _keyManager: KeyManager;
	private _keyId: string | null;
	private _onKeyChanged: () => Promise<void>;
	private _isCreateMode: boolean;

	private constructor(
		panel: vscode.WebviewPanel,
		extensionUri: vscode.Uri,
		keyId: string | null,
		keyManager: KeyManager,
		onKeyChanged: () => Promise<void>
	) {
		this._panel = panel;
		this._extensionUri = extensionUri;
		this._keyId = keyId;
		this._keyManager = keyManager;
		this._onKeyChanged = onKeyChanged;
		this._isCreateMode = keyId === null;

		this._panel.webview.html = this._getHtmlContent();

		// Handle messages from webview
		this._panel.webview.onDidReceiveMessage(
			async (message) => {
				if (message.type === 'ready') {
					if (this._isCreateMode) {
						this._panel.webview.postMessage({ type: 'createMode' });
					} else {
						await this.loadKeyData();
					}
				} else if (message.type === 'createManualKey') {
					await this.handleCreateManualKey(message.name, message.description, message.keyData, message.algorithm, message.keyType, message.claims);
				} else if (message.type === 'createURLKey') {
					await this.handleCreateURLKey(message.name, message.description, message.url, message.refreshPeriod);
				} else if (message.type === 'createJWKSJsonKey') {
					await this.handleCreateJWKSJsonKey(message.name, message.description, message.jwksJson);
				} else if (message.type === 'updateKey') {
					await this.handleUpdateKey(message.name, message.description, message.keyData, message.algorithm, message.refreshPeriod, message.keyType, message.claims, message.preferredKeyRef, message.jwksJson);
				} else if (message.type === 'deleteKey') {
					await this.handleDeleteKey(message.id);
				} else if (message.type === 'refreshKey') {
					await this.handleRefreshKey();
				}
			},
			null,
			this._disposables
		);

		this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
	}

	public static createOrShow(
		extensionUri: vscode.Uri,
		keyId: string | null,
		keyManager: KeyManager,
		onKeyChanged: () => Promise<void>
	): void {
		// If we already have a panel, dispose it and create a new one
		if (KeyDetailsPanel.currentPanel) {
			KeyDetailsPanel.currentPanel.dispose();
		}

		const title = keyId === null ? 'Add New Key' : 'Key Details';
		const panel = vscode.window.createWebviewPanel(
			'keyDetails',
			title,
			vscode.ViewColumn.One,
			{
				enableScripts: true,
				localResourceRoots: [getMediaRootUri(extensionUri)]
			}
		);

		KeyDetailsPanel.currentPanel = new KeyDetailsPanel(
			panel,
			extensionUri,
			keyId,
			keyManager,
			onKeyChanged
		);
	}

	private async loadKeyData(): Promise<void> {
		if (!this._keyId) {
			return;
		}
		const key = await this._keyManager.getKeyById(this._keyId);
		if (!key) {
			vscode.window.showErrorMessage('Key not found');
			this._panel.dispose();
			return;
		}

		this._panel.title = `Key Details: ${key.name}`;

		const editorData = this._keyManager.getKeyEditorData(key);
		
		this._panel.webview.postMessage({
			type: 'keyData',
			key: {
				id: key.id,
				name: key.name,
				description: key.description,
				source: key.source,
				keyData: editorData.decodedKey,
				claims: editorData.claims,
				rawJson: editorData.rawJson,
				algorithm: editorData.algorithm,
				typ: editorData.typ,
				kid: editorData.kid,
				preferredKeyRef: editorData.preferredKeyRef,
				availableKeyOptions: editorData.availableKeyOptions,
				url: isURLKey(key) ? key.url : undefined,
				refreshPeriod: isURLKey(key) ? key.refreshPeriod : undefined,
				jwksJson: isJWKSJsonKey(key) ? key.rawJwksJson : undefined,
				createdAt: key.createdAt,
				lastFetchedAt: isURLKey(key) ? key.lastFetchedAt : undefined,
				nextRefreshAt: isURLKey(key) ? key.nextRefreshAt : undefined
			}
		});
	}

	private async handleCreateManualKey(name: string, description: string, keyData: string, algorithm: string, keyType?: string, claims?: Record<string, unknown>): Promise<void> {
		const result = await this._keyManager.addManualKey(name, keyData, algorithm || 'RS256', keyType || 'RSA', claims, description);
		if (result.success) {
			vscode.window.showInformationMessage(`Key "${name}" added successfully`);
			await this._onKeyChanged();
			this._panel.dispose();
		} else {
			this.showError(result.error || 'Failed to add key');
		}
	}

	private async handleCreateURLKey(name: string, description: string, url: string, refreshPeriod: string): Promise<void> {
		await vscode.window.withProgress({
			location: vscode.ProgressLocation.Notification,
			title: `Fetching key from ${url}...`,
			cancellable: false
		}, async () => {
			const result = await this._keyManager.addURLKey(name, url, refreshPeriod as any, description);
			
			if (result.success) {
				vscode.window.showInformationMessage(`Key "${name}" fetched and added successfully`);
				await this._onKeyChanged();
				this._panel.dispose();
			} else {
				this.showError(result.error || 'Failed to fetch key from URL');
			}
		});
	}

	private async handleCreateJWKSJsonKey(name: string, description: string, jwksJson: string): Promise<void> {
		const result = await this._keyManager.addJWKSJsonKey(name, jwksJson, description);
		if (result.success) {
			vscode.window.showInformationMessage(`Key "${name}" added successfully`);
			await this._onKeyChanged();
			this._panel.dispose();
		} else {
			this.showError(result.error || 'Failed to add JWKS JSON key');
		}
	}

	private async handleUpdateKey(name: string, description: string, keyData: string, algorithm: string, refreshPeriod?: string, keyType?: string, claims?: Record<string, unknown>, preferredKeyRef?: string, jwksJson?: string): Promise<void> {
		if (!this._keyId) {
			return;
		}
		const key = await this._keyManager.getKeyById(this._keyId);
		if (!key) {
			this.showError('Key not found');
			return;
		}

		const result = isURLKey(key)
			? await this._keyManager.updateURLKeySettings(this._keyId, name, (refreshPeriod as RefreshPeriod) || key.refreshPeriod, preferredKeyRef, description)
			: isJWKSJsonKey(key)
				? await this._keyManager.updateJWKSJsonKey(this._keyId, name, typeof jwksJson === 'string' ? jwksJson : key.rawJwksJson, description)
				: await this._keyManager.updateManualKey(this._keyId, name, keyData, algorithm || 'RS256', keyType || 'RSA', claims, preferredKeyRef, description);
		if (result.success) {
			vscode.window.showInformationMessage(isURLKey(key) ? 'URL key updated successfully' : 'Key updated successfully');
			await this._onKeyChanged();
			await this.loadKeyData();
		} else {
			this.showError(result.error || 'Failed to update key');
		}
	}

	private async handleDeleteKey(messageKeyId?: string): Promise<void> {
		const keyId = messageKeyId || this._keyId;
		if (!keyId) {
			return;
		}
		await confirmAndDeleteKey(this._keyManager, keyId, async () => {
			await this._onKeyChanged();
			this._panel.dispose();
		});
	}

	private async handleRefreshKey(): Promise<void> {
		if (!this._keyId) {
			return;
		}
		const key = await this._keyManager.getKeyById(this._keyId);
		if (!key || !isURLKey(key)) {
			this.showError('Can only refresh URL-based keys');
			return;
		}

		await vscode.window.withProgress({
			location: vscode.ProgressLocation.Notification,
			title: 'Refreshing key...',
			cancellable: false
		}, async () => {
			if (!this._keyId) {
				return;
			}
			const result = await this._keyManager.refreshURLKey(this._keyId);
			
			if (result.success) {
				vscode.window.showInformationMessage('Key refreshed successfully');
				await this._onKeyChanged();
				await this.loadKeyData();
			} else {
				this.showError(result.error || 'Failed to refresh key');
			}
		});
	}

	private showError(error: string): void {
		this._panel.webview.postMessage({ type: 'error', error });
		vscode.window.showErrorMessage(error);
	}

	public dispose(): void {
		KeyDetailsPanel.currentPanel = undefined;
		this._panel.dispose();
		while (this._disposables.length) {
			const disposable = this._disposables.pop();
			if (disposable) {
				disposable.dispose();
			}
		}
	}

	private _getHtmlContent(): string {
		const assetUris = createAssetUris(this._extensionUri, this._panel.webview, 'keyDetails');
		return loadHtmlTemplate(this._extensionUri, this._panel.webview, 'keyDetails.html', assetUris);
	}
}
