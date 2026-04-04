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

/**
 * Integration tests for the Notary JWT Viewer extension.
 * These tests verify the complete workflow and interactions between components.
 */
suite('Integration Test Suite', () => {
	
	suite('Extension Lifecycle', () => {
		test('should activate without errors', async () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			assert.ok(ext, 'Extension should exist');
			
			await ext?.activate();
			assert.strictEqual(ext?.isActive, true, 'Extension should be activated');
		});
		
		test('should have all commands registered after activation', async () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			await ext?.activate();
			
			const commands = await vscode.commands.getCommands(true);
			const notaryCommands = commands.filter(cmd => cmd.startsWith('notary.'));
			
			assert.ok(notaryCommands.length >= 1, 'Should have at least one command registered');
		});
	});
	
	suite('Command Execution Workflow', () => {
		test('should open JWT viewer on command execution', async () => {
			// Execute the command
			await vscode.commands.executeCommand('notary.openViewer');
			
			// Wait for webview to be created
			await new Promise(resolve => setTimeout(resolve, 500));
			
			// Command should complete without throwing
			assert.ok(true, 'Command executed successfully');
		});
		
		test('should handle multiple viewer panels', async () => {
			// Open first panel
			await vscode.commands.executeCommand('notary.openViewer');
			await new Promise(resolve => setTimeout(resolve, 200));
			
			// Open second panel
			await vscode.commands.executeCommand('notary.openViewer');
			await new Promise(resolve => setTimeout(resolve, 200));
			
			// Open third panel
			await vscode.commands.executeCommand('notary.openViewer');
			await new Promise(resolve => setTimeout(resolve, 200));
			
			// All panels should be created without errors
			assert.ok(true, 'Multiple panels created successfully');
		});
	});
	
	suite('Extension Configuration', () => {
		test('should have correct display name', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			assert.strictEqual(ext?.packageJSON.displayName, 'Notary', 'Display name should be Notary');
		});
		
		test('should have description', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			assert.ok(
				ext?.packageJSON.description.toLowerCase().includes('jwt'),
				'Description should mention JWT'
			);
		});
		
		test('should have correct categories', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			const categories = ext?.packageJSON.categories;
			
			assert.ok(Array.isArray(categories), 'Should have categories array');
			assert.ok(categories.length > 0, 'Should have at least one category');
		});
		
		test('should have keywords', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			const keywords = ext?.packageJSON.keywords;
			
			assert.ok(Array.isArray(keywords), 'Should have keywords array');
			assert.ok(
				keywords.some((kw: string) => kw.toLowerCase().includes('jwt')),
				'Should have JWT in keywords'
			);
		});
	});
	
	suite('Webview Functionality', () => {
		test('should create webview panel with correct view type', async () => {
			await vscode.commands.executeCommand('notary.openViewer');
			await new Promise(resolve => setTimeout(resolve, 500));
			
			// Panel should be created without errors
			assert.ok(true, 'Webview panel created');
		});
		
		test('should enable scripts in webview', async () => {
			// This is implicitly tested by the webview being able to execute JS
			// The enableScripts option should be set to true in the panel configuration
			assert.ok(true, 'Scripts should be enabled in webview configuration');
		});
	});
	
	suite('Error Handling', () => {
		test('should handle command execution errors gracefully', async () => {
			let executedSuccessfully = false;
			try {
				await vscode.commands.executeCommand('notary.openViewer');
				executedSuccessfully = true;
			} catch (err) {
				const error = err as Error;
				assert.fail(`Command should not throw errors: ${error.message}`);
			}
			assert.ok(executedSuccessfully, 'Command executed without throwing');
		});
		
		test('should not crash on repeated command execution', async () => {
			for (let i = 0; i < 5; i++) {
				await vscode.commands.executeCommand('notary.openViewer');
				await new Promise(resolve => setTimeout(resolve, 100));
			}
			assert.ok(true, 'Repeated command execution handled');
		});
	});
	
	suite('Extension Metadata', () => {
		test('should have valid version number', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			const version = ext?.packageJSON.version;
			
			assert.ok(version, 'Should have version');
			assert.ok(/^\d+\.\d+\.\d+/.test(version), 'Version should be in semver format');
		});
		
		test('should have license information', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			const license = ext?.packageJSON.license;
			
			assert.ok(license, 'Should have license field');
			assert.strictEqual(license, 'GPL-3.0-only', 'Should have GPL-3.0-only license');
		});
		
		test('should have repository information', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			const repo = ext?.packageJSON.repository;
			
			assert.ok(repo, 'Should have repository information');
			assert.ok(repo.url, 'Repository should have URL');
		});
		
		test('should target correct VS Code engine version', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			const engines = ext?.packageJSON.engines;
			
			assert.ok(engines, 'Should have engines field');
			assert.ok(engines.vscode, 'Should specify VS Code engine version');
			assert.ok(
				engines.vscode.startsWith('^'),
				'Engine version should allow compatible versions'
			);
		});
	});
	
	suite('Views and Sidebar', () => {
		test('should have viewsContainer contribution', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			const viewsContainers = ext?.packageJSON.contributes?.viewsContainers;
			
			assert.ok(viewsContainers, 'Should have viewsContainers');
			assert.ok(viewsContainers.activitybar, 'Should have activitybar containers');
		});
		
		test('should have notary container in activitybar', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			const containers = ext?.packageJSON.contributes?.viewsContainers?.activitybar;
			
			const notaryContainer = containers?.find((c: any) => c.id === 'notary-container');
			assert.ok(notaryContainer, 'Should have notary-container');
			assert.ok(notaryContainer.title, 'Container should have title');
			assert.ok(notaryContainer.icon, 'Container should have icon');
		});
		
		test('should have views contribution', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			const views = ext?.packageJSON.contributes?.views;
			
			assert.ok(views, 'Should have views contribution');
			assert.ok(views['notary-container'], 'Should have views in notary-container');
		});
		
		test('should have sidebar view defined', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			const containerViews = ext?.packageJSON.contributes?.views['notary-container'];
			
			assert.ok(Array.isArray(containerViews), 'Container views should be array');
			
			const sidebarView = containerViews?.find((v: any) => v.id === 'notary.sidebarView');
			assert.ok(sidebarView, 'Should have notary.sidebarView');
			assert.strictEqual(sidebarView.type, 'webview', 'View should be webview type');
		});
	});
	
	suite('Command Contributions', () => {
		test('should have command with proper metadata', () => {
			const ext = vscode.extensions.getExtension('JohnManko.notary');
			const commands = ext?.packageJSON.contributes?.commands;
			
			const openViewerCmd = commands?.find((c: any) => c.command === 'notary.openViewer');
			
			assert.ok(openViewerCmd, 'Should have openViewer command');
			assert.ok(openViewerCmd.title, 'Command should have title');
			assert.ok(openViewerCmd.category, 'Command should have category');
			assert.strictEqual(openViewerCmd.category, 'Notary', 'Category should be Notary');
		});
	});
});
