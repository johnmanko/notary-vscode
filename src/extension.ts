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
import { JwtViewerPanel, PanelStateChangeCallback } from './jwtViewerPanel';
import { JwtViewerSidebarProvider, PanelInfo } from './jwtViewerSidebarProvider';

interface PanelEntry {
	id: string;
	panel: JwtViewerPanel;
	createdAt: Date;
	snippet: string;
}

const panelRegistry = new Map<string, PanelEntry>();
let sidebarProvider: JwtViewerSidebarProvider;

function buildSidebarList(): PanelInfo[] {
	return Array.from(panelRegistry.values()).map(e => ({
		id: e.id,
		label: e.snippet || '(empty)',
		createdAt: e.createdAt.toISOString(),
	}));
}

function pushSidebarUpdate() {
	sidebarProvider?.updatePanelList(buildSidebarList());
}

function createPanel(extensionUri: vscode.Uri) {
	const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
	const createdAt = new Date();

	const onStateChange: PanelStateChangeCallback = (snippet) => {
		if (snippet === null) {
			panelRegistry.delete(id);
		} else {
			const entry = panelRegistry.get(id);
			if (entry) { entry.snippet = snippet; }
		}
		pushSidebarUpdate();
	};

	const keyManager = sidebarProvider?.getKeyManager();
	const panel = JwtViewerPanel.create(id, createdAt, extensionUri, onStateChange, keyManager);
	panelRegistry.set(id, { id, panel, createdAt, snippet: '' });
	pushSidebarUpdate();
}

async function updateAllPanelKeys() {
	for (const entry of panelRegistry.values()) {
		await entry.panel.updateKeyList();
	}
}

export function activate(context: vscode.ExtensionContext) {
	sidebarProvider = new JwtViewerSidebarProvider(
		context.extensionUri,
		context,
		() => createPanel(context.extensionUri),
		(id) => {
			const entry = panelRegistry.get(id);
			if (entry) { entry.panel.reveal(); }
		},
		() => buildSidebarList()
	);

	// Set callback to update all panels when keys change
	sidebarProvider.setKeyChangeCallback(updateAllPanelKeys);

	context.subscriptions.push(
		vscode.window.registerWebviewViewProvider(JwtViewerSidebarProvider.viewId, sidebarProvider),
		vscode.commands.registerCommand('notary.openViewer', () => createPanel(context.extensionUri))
	);
}

export function deactivate() {
	// Cleanup if needed
}

