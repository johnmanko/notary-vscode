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
import { KeyManager } from './keyManager';

/**
 * Shared delete flow for validation keys used by both sidebar and key details panel.
 */
export async function confirmAndDeleteKey(
	keyManager: KeyManager,
	keyId: string,
	onDeleted: () => Promise<void>
): Promise<void> {
	const confirm = await vscode.window.showWarningMessage(
		'Are you sure you want to delete this validation key?',
		{ modal: true },
		'Delete'
	);

	if (confirm !== 'Delete') {
		return;
	}

	const success = await keyManager.deleteKey(keyId);
	if (!success) {
		vscode.window.showErrorMessage('Failed to delete key');
		return;
	}

	vscode.window.showInformationMessage('Key deleted successfully');
	await onDeleted();
}
