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

import * as assert from 'node:assert';
import * as vscode from 'vscode';
import { getNonce, createAssetUris } from '../src/utils/webviewUtils';

suite('Webview Utils Test Suite', () => {
	
	suite('getNonce', () => {
		test('should generate a 32-character nonce', () => {
			const nonce = getNonce();
			assert.strictEqual(nonce.length, 32, 'Nonce should be 32 characters long');
		});
		
		test('should generate alphanumeric nonce', () => {
			const nonce = getNonce();
			const alphanumericRegex = /^[A-Za-z0-9]+$/;
			assert.ok(alphanumericRegex.test(nonce), 'Nonce should be alphanumeric');
		});
		
		test('should generate different nonces', () => {
			const nonce1 = getNonce();
			const nonce2 = getNonce();
			assert.notStrictEqual(nonce1, nonce2, 'Each nonce should be unique');
		});
		
		test('should generate nonces with good randomness', () => {
			const nonces = new Set();
			for (let i = 0; i < 100; i++) {
				nonces.add(getNonce());
			}
			assert.strictEqual(nonces.size, 100, 'All 100 nonces should be unique');
		});
	});
	
	suite('createAssetUris', () => {
		let mockExtensionUri: vscode.Uri;
		let mockWebview: vscode.Webview;
		
		setup(() => {
			mockExtensionUri = vscode.Uri.file('/mock/extension/path');
			
			// Create a mock webview
			mockWebview = {
				asWebviewUri: (uri: vscode.Uri) => {
					return vscode.Uri.parse(`vscode-webview://mock/${uri.path}`);
				}
			} as any;
		});
		
		test('should create URI for CSS file', () => {
			const uris = createAssetUris(mockExtensionUri, mockWebview, 'testFile');
			
			assert.ok(uris['{{STYLE_URI}}'], 'Should have STYLE_URI key');
			assert.ok(
				uris['{{STYLE_URI}}'].includes('testFile.css'),
				'CSS URI should include filename'
			);
		});
		
		test('should create URI for JS file', () => {
			const uris = createAssetUris(mockExtensionUri, mockWebview, 'testFile');
			
			assert.ok(uris['{{SCRIPT_URI}}'], 'Should have SCRIPT_URI key');
			assert.ok(
				uris['{{SCRIPT_URI}}'].includes('testFile.js'),
				'JS URI should include filename'
			);
		});
		
		test('should create webview URIs', () => {
			const uris = createAssetUris(mockExtensionUri, mockWebview, 'panel');
			
			assert.ok(
				uris['{{STYLE_URI}}'].startsWith('vscode-webview://'),
				'Style URI should be a webview URI'
			);
			assert.ok(
				uris['{{SCRIPT_URI}}'].startsWith('vscode-webview://'),
				'Script URI should be a webview URI'
			);
		});
		
		test('should include media directory in path', () => {
			const uris = createAssetUris(mockExtensionUri, mockWebview, 'viewer');
			
			assert.ok(
				uris['{{STYLE_URI}}'].includes('media'),
				'URI should include media directory'
			);
			assert.ok(
				uris['{{SCRIPT_URI}}'].includes('media'),
				'URI should include media directory'
			);
		});
		
		test('should handle different base names', () => {
			const uris1 = createAssetUris(mockExtensionUri, mockWebview, 'panel');
			const uris2 = createAssetUris(mockExtensionUri, mockWebview, 'sidebar');
			
			assert.ok(
				uris1['{{STYLE_URI}}'].includes('panel'),
				'Should use first base name'
			);
			assert.ok(
				uris2['{{STYLE_URI}}'].includes('sidebar'),
				'Should use second base name'
			);
			assert.notStrictEqual(
				uris1['{{STYLE_URI}}'],
				uris2['{{STYLE_URI}}'],
				'Different base names should produce different URIs'
			);
		});
	});
});
