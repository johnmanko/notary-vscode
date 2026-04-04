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
import { escapeHtml } from '../src/webview/utils';

suite('Webview Escape Utils Test Suite', () => {
	
	suite('escapeHtml', () => {
		test('should escape ampersands', () => {
			const result = escapeHtml('foo & bar');
			assert.strictEqual(result, 'foo &amp; bar');
		});
		
		test('should escape less-than signs', () => {
			const result = escapeHtml('5 < 10');
			assert.strictEqual(result, '5 &lt; 10');
		});
		
		test('should escape greater-than signs', () => {
			const result = escapeHtml('10 > 5');
			assert.strictEqual(result, '10 &gt; 5');
		});
		
		test('should escape double quotes', () => {
			const result = escapeHtml('He said "hello"');
			assert.strictEqual(result, 'He said &quot;hello&quot;');
		});
		
		test('should escape all special characters together', () => {
			const result = escapeHtml('<div class="test">A & B</div>');
			assert.strictEqual(result, '&lt;div class=&quot;test&quot;&gt;A &amp; B&lt;/div&gt;');
		});
		
		test('should handle empty string', () => {
			const result = escapeHtml('');
			assert.strictEqual(result, '');
		});
		
		test('should handle string with no special characters', () => {
			const result = escapeHtml('hello world');
			assert.strictEqual(result, 'hello world');
		});
		
		test('should handle numbers', () => {
			const result = escapeHtml(12345);
			assert.strictEqual(result, '12345');
		});
		
		test('should handle boolean values', () => {
			const result1 = escapeHtml(true);
			const result2 = escapeHtml(false);
			assert.strictEqual(result1, 'true');
			assert.strictEqual(result2, 'false');
		});
		
		test('should handle null', () => {
			const result = escapeHtml(null);
			assert.strictEqual(result, 'null');
		});
		
		test('should handle undefined', () => {
			const result = escapeHtml(undefined);
			assert.strictEqual(result, 'undefined');
		});
		
		test('should escape multiple occurrences of same character', () => {
			const result = escapeHtml('&&&');
			assert.strictEqual(result, '&amp;&amp;&amp;');
		});
		
		test('should handle mixed special characters', () => {
			const result = escapeHtml('&<>"\'"');
			assert.strictEqual(result, '&amp;&lt;&gt;&quot;\'&quot;');
		});
		
		test('should preserve single quotes', () => {
			const result = escapeHtml("It's a test");
			assert.strictEqual(result, "It's a test");
		});
		
		test('should handle script tags', () => {
			const result = escapeHtml('<script>alert("XSS")</script>');
			assert.strictEqual(result, '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;');
		});
		
		test('should prevent XSS attacks', () => {
			const malicious = '<img src=x onerror="alert(\'XSS\')">';
			const result = escapeHtml(malicious);
			assert.ok(!result.includes('<img'), 'Should not contain img tag');
			assert.ok(result.includes('onerror'), 'Should contain escaped onerror');
		});
		
		test('should handle JWT-like strings', () => {
			const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
			const result = escapeHtml(jwt);
			assert.strictEqual(result, jwt, 'JWT string should remain unchanged');
		});
		
		test('should handle JSON strings', () => {
			const json = '{"key":"value"}';
			const result = escapeHtml(json);
			assert.strictEqual(result, '{&quot;key&quot;:&quot;value&quot;}');
		});
	});
});
