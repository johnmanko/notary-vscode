const esbuild = require("esbuild");
const fs = require("node:fs");
const path = require("node:path");

const production = process.argv.includes('--production');
const watch = process.argv.includes('--watch');

/**
 * @type {import('esbuild').Plugin}
 */
const esbuildProblemMatcherPlugin = {
	name: 'esbuild-problem-matcher',

	setup(build) {
		build.onStart(() => {
			console.log('[watch] build started');
		});
		build.onEnd((result) => {
			result.errors.forEach(({ text, location }) => {
				console.error(`✘ [ERROR] ${text}`);
				console.error(`    ${location.file}:${location.line}:${location.column}:`);
			});
			console.log('[watch] build finished');
		});
	},
};

function ensureDir(dirPath) {
	fs.mkdirSync(dirPath, { recursive: true });
}

function copyRuntimeAssets() {
	const projectRoot = process.cwd();
	const srcMediaDir = path.join(projectRoot, 'media');
	const distMediaDir = path.join(projectRoot, 'dist', 'media');
	const srcImagesDir = path.join(projectRoot, 'images');
	const distImagesDir = path.join(projectRoot, 'dist', 'images');

	ensureDir(distMediaDir);
	ensureDir(distImagesDir);

	if (fs.existsSync(srcMediaDir)) {
		for (const file of fs.readdirSync(srcMediaDir)) {
			if (!file.endsWith('.html') && !file.endsWith('.css')) {
				continue;
			}
			fs.copyFileSync(path.join(srcMediaDir, file), path.join(distMediaDir, file));
		}
	}

	for (const iconFile of ['icon.png', 'icon.svg']) {
		const src = path.join(srcImagesDir, iconFile);
		if (fs.existsSync(src)) {
			fs.copyFileSync(src, path.join(distImagesDir, iconFile));
		}
	}
}

async function main() {
	// ── Extension host (Node context) ──────────────────────────────────────
	const extCtx = await esbuild.context({
		entryPoints: [
			'src/extension.ts'
		],
		bundle: true,
		format: 'cjs',
		minify: production,
		sourcemap: !production,
		sourcesContent: false,
		platform: 'node',
		outfile: 'dist/extension.js',
		external: ['vscode'],
		logLevel: 'silent',
		plugins: [esbuildProblemMatcherPlugin],
	});

	// ── Webview scripts (browser context) ──────────────────────────────────
	const webviewCtx = await esbuild.context({
		entryPoints: {
			jwtViewerPanel: 'src/webview/jwtViewerPanel.ts',
			jwtViewerSidebar: 'src/webview/jwtViewerSidebar.ts',
			keyDetails: 'src/webview/utils/keyDetails.ts',
		},
		bundle: true,
		format: 'iife',
		minify: production,
		sourcemap: !production,
		sourcesContent: false,
		platform: 'browser',
		outdir: 'dist/media',
		logLevel: 'silent',
		plugins: [esbuildProblemMatcherPlugin],
	});

	if (watch) {
		copyRuntimeAssets();
		await Promise.all([extCtx.watch(), webviewCtx.watch()]);
	} else {
		await extCtx.rebuild();
		await extCtx.dispose();
		await webviewCtx.rebuild();
		copyRuntimeAssets();
		await webviewCtx.dispose();
	}
}

main().catch(e => {
	console.error(e);
	process.exit(1);
});
