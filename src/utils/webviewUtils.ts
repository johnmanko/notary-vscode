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
import * as fs from 'node:fs';
import * as path from 'node:path';

export function getMediaPathSegments(extensionUri: vscode.Uri): string[] {
	const distMediaPath = path.join(extensionUri.fsPath, 'dist', 'media');
	return fs.existsSync(distMediaPath) ? ['dist', 'media'] : ['media'];
}

export function getMediaRootUri(extensionUri: vscode.Uri): vscode.Uri {
	return vscode.Uri.joinPath(extensionUri, ...getMediaPathSegments(extensionUri));
}

/**
 * Generates a cryptographically random nonce for CSP in webviews.
 * @returns A 32-character alphanumeric string
 */
export function getNonce(): string {
	let text = '';
	const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	for (let i = 0; i < 32; i++) {
		text += possible.charAt(Math.floor(Math.random() * possible.length));
	}
	return text;
}

/**
 * Loads an HTML template file and replaces placeholders with provided values.
 * @param extensionUri - The extension's URI
 * @param webview - The webview instance
 * @param templateName - Name of the HTML file in the media directory
 * @param additionalReplacements - Additional placeholder replacements (optional)
 * @returns The processed HTML string
 */
export function loadHtmlTemplate(
	extensionUri: vscode.Uri,
	webview: vscode.Webview,
	templateName: string,
	additionalReplacements?: Record<string, string>
): string {
	const nonce = getNonce();
	const mediaDir = path.join(extensionUri.fsPath, ...getMediaPathSegments(extensionUri));
	const templatePath = path.join(mediaDir, templateName);

	let html = fs.readFileSync(templatePath, 'utf8');

	// Standard replacements
	const replacements: Record<string, string> = {
		'{{NONCE}}': nonce,
		'{{CSP_SOURCE}}': webview.cspSource,
		...additionalReplacements,
	};

	// Apply all replacements
	for (const [placeholder, value] of Object.entries(replacements)) {
		html = html.replaceAll(placeholder, value);
	}

	return html;
}

/**
 * Creates webview URI replacements for CSS and JS files.
 * @param extensionUri - The extension's URI
 * @param webview - The webview instance
 * @param baseName - Base name for the CSS and JS files (without extension)
 * @returns Object with STYLE_URI and SCRIPT_URI keys
 */
export function createAssetUris(
	extensionUri: vscode.Uri,
	webview: vscode.Webview,
	baseName: string
): Record<string, string> {
	const mediaPathSegments = getMediaPathSegments(extensionUri);
	return {
		'{{STYLE_URI}}': webview.asWebviewUri(
			vscode.Uri.joinPath(extensionUri, ...mediaPathSegments, `${baseName}.css`)
		).toString(),
		'{{SCRIPT_URI}}': webview.asWebviewUri(
			vscode.Uri.joinPath(extensionUri, ...mediaPathSegments, `${baseName}.js`)
		).toString(),
	};
}
