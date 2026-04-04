const fs = require('node:fs');
const path = require('node:path');

function ensureDir(dirPath) {
	fs.mkdirSync(dirPath, { recursive: true });
}

function copyFileIfExists(srcPath, destPath) {
	if (!fs.existsSync(srcPath)) {
		return;
	}
	ensureDir(path.dirname(destPath));
	fs.copyFileSync(srcPath, destPath);
}

function rewriteDistPaths(value) {
	if (typeof value === 'string') {
		if (value.startsWith('./dist/')) {
			return `./${value.slice('./dist/'.length)}`;
		}
		if (value.startsWith('dist/')) {
			return value.slice('dist/'.length);
		}
		return value;
	}

	if (Array.isArray(value)) {
		return value.map(rewriteDistPaths);
	}

	if (value && typeof value === 'object') {
		const out = {};
		for (const [k, v] of Object.entries(value)) {
			out[k] = rewriteDistPaths(v);
		}
		return out;
	}

	return value;
}

function buildDistPackageJson(rootPackageJson) {
	const keep = {
		name: rootPackageJson.name,
		displayName: rootPackageJson.displayName,
		description: rootPackageJson.description,
		version: rootPackageJson.version,
		license: rootPackageJson.license,
		engines: rootPackageJson.engines,
		publisher: rootPackageJson.publisher,
		repository: rootPackageJson.repository,
		bugs: rootPackageJson.bugs,
		galleryBanner: rootPackageJson.galleryBanner,
		keywords: rootPackageJson.keywords,
		categories: rootPackageJson.categories,
		icon: rootPackageJson.icon,
		main: rootPackageJson.main,
		contributes: rootPackageJson.contributes,
		activationEvents: rootPackageJson.activationEvents,
	};

	const rewritten = rewriteDistPaths(keep);
	rewritten.scripts = {};
	return rewritten;
}

function main() {
	const rootDir = process.cwd();
	const distDir = path.join(rootDir, 'dist');
	if (!fs.existsSync(distDir)) {
		throw new Error('dist folder does not exist. Run npm run package first.');
	}

	const metadataFiles = [
		'package-lock.json',
		'README.md',
		'CHANGELOG.md',
		'LICENSE',
		'NOTICE',
	];

	for (const fileName of metadataFiles) {
		copyFileIfExists(path.join(rootDir, fileName), path.join(distDir, fileName));
	}

	const rootPackageJson = JSON.parse(
		fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8')
	);
	const distPackageJson = buildDistPackageJson(rootPackageJson);
	fs.writeFileSync(
		path.join(distDir, 'package.json'),
		JSON.stringify(distPackageJson, null, 2) + '\n',
		'utf8'
	);

	const distIgnore = [
		'**/*.map',
		'notary-*.vsix',
		'.vscodeignore',
	].join('\n') + '\n';
	fs.writeFileSync(path.join(distDir, '.vscodeignore'), distIgnore, 'utf8');
}

main();
