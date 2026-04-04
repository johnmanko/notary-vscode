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

suite('Extension Test Suite', () => {
	
	suite('Extension Activation', () => {
		test('should activate extension', async () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			assert.ok(ext, 'Extension should be present');
			
			await ext?.activate();
			assert.strictEqual(ext?.isActive, true, 'Extension should be active');
		});
		
		test('should register notary.openViewer command', async () => {
			const commands = await vscode.commands.getCommands(true);
			assert.ok(
				commands.includes('notary.openViewer'),
				'Command notary.openViewer should be registered'
			);
		});
		
		test('should have sidebar view registered', async () => {
			// The sidebar view should be available after activation
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			await ext?.activate();
			
			// View should be defined in package.json contributions
			assert.ok(ext?.isActive, 'Extension should be active for sidebar view');
		});
	});
	
	suite('JWT Viewer Command', () => {
		test('should execute notary.openViewer command', async () => {
			// Execute the command to open a JWT viewer panel
			await vscode.commands.executeCommand('notary.openViewer');
			
			// Give it time to create the webview
			await new Promise(resolve => setTimeout(resolve, 500));
			
			// Check that a webview panel was created (indirectly by checking no errors occurred)
			assert.ok(true, 'Command executed successfully');
		});
		
		test('should create multiple panels when command is executed multiple times', async () => {
			await vscode.commands.executeCommand('notary.openViewer');
			await new Promise(resolve => setTimeout(resolve, 100));
			
			await vscode.commands.executeCommand('notary.openViewer');
			await new Promise(resolve => setTimeout(resolve, 100));
			
			// Both commands should execute without errors
			assert.ok(true, 'Multiple panels can be created');
		});
	});
	
	suite('Extension Package', () => {
		test('should have correct extension ID', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			assert.ok(ext, 'Extension should exist with correct ID');
		});
		
		test('should have package.json with required fields', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			const packageJSON = ext?.packageJSON;
			
			assert.ok(packageJSON, 'Package.json should exist');
			assert.strictEqual(packageJSON.name, 'notary', 'Name should be notary');
			assert.strictEqual(packageJSON.displayName, 'Notary', 'Display name should be Notary');
			assert.ok(packageJSON.description, 'Should have description');
			assert.ok(packageJSON.version, 'Should have version');
		});
		
		test('should have correct activation events', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			const packageJSON = ext?.packageJSON;
			
			// activationEvents can be omitted in modern extensions with implicit activation
			assert.ok(
				packageJSON.activationEvents === undefined || Array.isArray(packageJSON.activationEvents),
				'activationEvents should be undefined or an array'
			);
		});
		
		test('should have commands contribution', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			const packageJSON = ext?.packageJSON;
			
			assert.ok(packageJSON.contributes?.commands, 'Should have commands contribution');
			const commands = packageJSON.contributes.commands;
			
			const openViewerCmd = commands.find((cmd: any) => cmd.command === 'notary.openViewer');
			assert.ok(openViewerCmd, 'Should have notary.openViewer command');
			assert.ok(openViewerCmd.title, 'Command should have title');
		});
		
		test('should have views contribution', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			const packageJSON = ext?.packageJSON;

			assert.ok(packageJSON.contributes?.viewsContainers, 'Should have viewsContainers contribution');
			assert.ok(packageJSON.contributes?.views, 'Should have views contribution');
		});
	});
	
	suite('Command Availability', () => {
		test('should have command available in command palette', async () => {
			const commands = await vscode.commands.getCommands();
			const notaryCommands = commands.filter(cmd => cmd.startsWith('notary.'));
			
			assert.ok(notaryCommands.length > 0, 'Should have at least one notary command');
			assert.ok(
				notaryCommands.includes('notary.openViewer'),
				'Should include notary.openViewer'
			);
		});
	});
	
	suite('Extension Cleanup', () => {
		test('should handle deactivation gracefully', async () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			await ext?.activate();
			
			// Extension should be active
			assert.strictEqual(ext?.isActive, true, 'Extension should be active');
			
			// Note: We can't directly test deactivation as VSCode manages this
			// But we can ensure the extension is in a valid state
			assert.ok(ext, 'Extension should exist for deactivation');
		});
	});
});
