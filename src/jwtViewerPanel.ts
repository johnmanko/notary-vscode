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
import { validateJWTSignature } from './utils/jwtValidator';
import { isManualKey } from './types/keyManagement';

export type PanelStateChangeCallback = (snippet: string | null) => void;

export class JwtViewerPanel {
	private static readonly viewType = 'notary';

	public readonly panelId: string;
	public readonly createdAt: Date;
	private _snippet: string = '';
	private _disposed = false;
	private readonly _panel: vscode.WebviewPanel;
	private readonly _disposables: vscode.Disposable[] = [];
	private readonly _keyManager?: KeyManager;

	public static create(
		panelId: string,
		createdAt: Date,
		extensionUri: vscode.Uri,
		onStateChange: PanelStateChangeCallback,
		keyManager?: KeyManager
	): JwtViewerPanel {
		const panel = vscode.window.createWebviewPanel(
			JwtViewerPanel.viewType,
			'JWT Viewer',
			vscode.ViewColumn.One,
			{
				enableScripts: true,
				retainContextWhenHidden: true,
				localResourceRoots: [getMediaRootUri(extensionUri)],
			}
		);
		return new JwtViewerPanel(panel, panelId, createdAt, extensionUri, onStateChange, keyManager);
	}

	private constructor(
		panel: vscode.WebviewPanel,
		panelId: string,
		createdAt: Date,
		private readonly _extensionUri: vscode.Uri,
		private readonly _onStateChange: PanelStateChangeCallback,
		keyManager?: KeyManager
	) {
		this._panel = panel;
		this.panelId = panelId;
		this.createdAt = createdAt;
		this._keyManager = keyManager;
		this._panel.webview.html = this._getHtmlContent(this._panel.webview);
		this._panel.webview.onDidReceiveMessage(
			async (message) => {
				if (message.type === 'jwtChanged') {
					const encoded = ((message.encoded as string) || '').trim();
					this._snippet = this._buildSnippet(encoded);
					this._panel.title = this._snippet ? `JWT: ${this._snippet}` : 'JWT Viewer';
					this._onStateChange(this._snippet);
				} else if (message.type === 'requestKeyList') {
					await this.sendKeyList();
				} else if (message.type === 'validateSignature') {
					await this.handleValidation(message.keyId, message.token);
				}
			},
			null,
			this._disposables
		);
		this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
	}

	private async sendKeyList(): Promise<void> {
		if (!this._keyManager) {
			return;
		}

		const keys = await this._keyManager.getAllKeys();
		const serializedKeys = keys.map(key => ({
			id: key.id,
			name: key.name,
			source: key.source
		}));

		this._panel.webview.postMessage({
			type: 'keyList',
			keys: serializedKeys
		});
	}

	private async handleValidation(keyId: string, token: string): Promise<void> {
		if (!this._keyManager) {
			this._panel.webview.postMessage({
				type: 'validationResult',
				isValid: false,
				message: 'Key manager not available'
			});
			return;
		}

		try {
			// Get and refresh key if needed
			const keyResult = await this._keyManager.getKeyAndRefreshIfNeeded(keyId);
			
			if (!keyResult.success || !keyResult.key) {
				this._panel.webview.postMessage({
					type: 'validationResult',
					isValid: false,
					message: keyResult.error || 'Failed to retrieve key'
				});
				return;
			}

			// Build a usable public key from stored model data
			const publicKey = this._keyManager.getPublicKeyForValidation(keyResult.key);
			const manualKeyMetadata = isManualKey(keyResult.key)
				? (() => {
					const editorData = this._keyManager.getKeyEditorData(keyResult.key);
					return {
						algorithm: editorData.algorithm || 'RS256',
						typ: editorData.typ || 'JWT'
					};
				})()
				: undefined;
			
			// Validate the signature
			const validationResult = await validateJWTSignature(token, publicKey, manualKeyMetadata);
			
			this._panel.webview.postMessage({
				type: 'validationResult',
				isValid: validationResult.valid,
				message: validationResult.message
			});

			// Show warning if key was refreshed
			if (keyResult.error) {
				vscode.window.showWarningMessage(keyResult.error);
			}

		} catch (error) {
			this._panel.webview.postMessage({
				type: 'validationResult',
				isValid: false,
				message: `Validation error: ${error instanceof Error ? error.message : 'Unknown error'}`
			});
		}
	}

	public async updateKeyList(): Promise<void> {
		await this.sendKeyList();
	}

	private _buildSnippet(encoded: string): string {
		if (!encoded) { return ''; }
		if (encoded.length <= 22) { return encoded; }
		return encoded.slice(0, 10) + '\u2026' + encoded.slice(-12);
	}

	public reveal() {
		this._panel.reveal();
	}

	public dispose() {
		if (this._disposed) { return; }
		this._disposed = true;
		this._onStateChange(null);
		this._panel.dispose();
		while (this._disposables.length) {
			const x = this._disposables.pop();
			if (x) { x.dispose(); }
		}
	}

	private _getHtmlContent(webview: vscode.Webview): string {
		const assetUris = createAssetUris(this._extensionUri, webview, 'jwtViewerPanel');
		return loadHtmlTemplate(this._extensionUri, webview, 'jwtViewerPanel.html', assetUris);
	}
}
