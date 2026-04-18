const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const rootDir = path.resolve(__dirname, '..');
const c8Bin = require.resolve('c8/bin/c8.js', { paths: [rootDir] });
const mochaBin = path.join(rootDir, 'node_modules', 'mocha', 'bin', 'mocha.js');
const defaultThresholds = {
	statements: 90,
	branches: 90,
	functions: 90,
	lines: 90
};

const suites = [
	{
		name: 'jwtDecoder',
		testFiles: [
			'dist-test/test/jwtDecoder.test.js',
			'dist-test/test/jwtEdgeCases.test.js'
		],
		includes: ['dist-test/src/utils/jwtDecoder.js'],
		sources: ['src/utils/jwtDecoder.ts']
	},
	{
		name: 'keyManagement',
		testFiles: ['dist-test/test/keyManagement.test.js'],
		includes: [
			'dist-test/src/types/keyManagement.js',
			'dist-test/src/utils/keyStorage.js',
			'dist-test/src/utils/oidcKeyFetcher.js',
			'dist-test/src/utils/jwtValidator.js'
		],
		sources: [
			'src/types/keyManagement.ts',
			'src/utils/keyStorage.ts',
			'src/utils/oidcKeyFetcher.ts',
			'src/utils/jwtValidator.ts'
		]
	},
	{
		name: 'keyManager',
		testFiles: [
			'dist-test/test/keyManagerHelpers.test.js',
			'dist-test/test/keyManagerSelection.test.js',
			'dist-test/test/keyManagerOperations.test.js'
		],
		includes: [
			'dist-test/src/utils/keyManager.js',
			'dist-test/src/utils/keyManagerHelpers.js'
		],
		sources: [
			'src/utils/keyManager.ts',
			'src/utils/keyManagerHelpers.ts'
		]
	},
	{
		name: 'webviewUtilities',
		testFiles: [
			'dist-test/test/escapeUtils.test.js',
			'dist-test/test/webviewUtils.test.js'
		],
		includes: [
			'dist-test/src/webview/utils.js',
			'dist-test/src/utils/webviewUtils.js',
		],
		sources: [
			'src/webview/utils.ts',
			'src/utils/webviewUtils.ts'
		]
	}
];

function parseArgs(argv) {
	const args = { suiteNames: [] };
	for (let index = 0; index < argv.length; index += 1) {
		const arg = argv[index];
		if ((arg === '--suite' || arg === '-s') && argv[index + 1]) {
			args.suiteNames.push(argv[index + 1]);
			index += 1;
		}
	}
	return args;
}

function getSelectedSuites() {
	const args = parseArgs(process.argv.slice(2));
	if (args.suiteNames.length === 0) {
		return suites;
	}

	const requested = new Set(args.suiteNames);
	const selected = suites.filter(suite => requested.has(suite.name));
	if (selected.length !== requested.size) {
		const missing = [...requested].filter(name => !selected.some(suite => suite.name === name));
		throw new Error(`Unknown suite name(s): ${missing.join(', ')}`);
	}
	return selected;
}

function removeDirectory(dirPath) {
	fs.rmSync(dirPath, { recursive: true, force: true });
}

function normalizePathForMatch(filePath) {
	return filePath.replaceAll('\\', '/');
}

function readCoverageSummary(reportDir) {
	const summaryPath = path.join(reportDir, 'coverage-summary.json');
	if (!fs.existsSync(summaryPath)) {
		throw new Error(`Coverage summary not found at ${summaryPath}`);
	}
	return JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
}

function findMetrics(summary, sourcePath) {
	const target = normalizePathForMatch(path.join(rootDir, sourcePath));
	for (const [summaryPath, metrics] of Object.entries(summary)) {
		if (summaryPath === 'total') {
			continue;
		}
		if (normalizePathForMatch(summaryPath) === target) {
			return metrics;
		}
	}
	return null;
}

function runCoverageForSuite(suite) {
	const tempDir = path.join(rootDir, 'coverage', 'tmp', `focused-${suite.name}`);
	const reportDir = path.join(rootDir, 'coverage', 'focused', suite.name);
	removeDirectory(tempDir);
	removeDirectory(reportDir);

	const args = [
		c8Bin,
		'--reporter=json-summary',
		'--all',
		`--temp-directory=${tempDir}`,
		`--reports-dir=${reportDir}`,
		...suite.includes.map(includePath => `--include=${includePath}`),
		process.execPath,
		mochaBin,
		'--require',
		'scripts/test-support/register-focused-mocks.cjs',
		'--ui',
		'tdd',
		...suite.testFiles
	];

	const result = spawnSync(process.execPath, args, {
		cwd: rootDir,
		encoding: 'utf8',
		stdio: 'pipe'
	});

	if (result.status !== 0) {
		process.stdout.write(result.stdout || '');
		process.stderr.write(result.stderr || '');
		throw new Error(`Coverage run failed for suite ${suite.name}`);
	}

	const summary = readCoverageSummary(reportDir);
	const files = suite.sources.map(sourcePath => {
		const metrics = findMetrics(summary, sourcePath);
		if (!metrics) {
			throw new Error(`Coverage summary for ${suite.name} did not contain ${sourcePath}`);
		}
		return { file: sourcePath, metrics };
	});

	const failures = [];
	for (const file of files) {
		for (const [metric, threshold] of Object.entries(defaultThresholds)) {
			if (file.metrics[metric].pct < threshold) {
				failures.push(`${file.file} ${metric} ${file.metrics[metric].pct}% < ${threshold}%`);
			}
		}
	}

	return {
		suite,
		files,
		failures,
		stdout: result.stdout
	};
}

function formatMetric(metrics) {
	return `S ${metrics.statements.pct}% | B ${metrics.branches.pct}% | F ${metrics.functions.pct}% | L ${metrics.lines.pct}%`;
}

function main() {
	const selectedSuites = getSelectedSuites();
	const results = selectedSuites.map(runCoverageForSuite);

	for (const result of results) {
		console.log(`\n[${result.suite.name}] ${result.suite.testFiles.join(', ')}`);
		for (const file of result.files) {
			console.log(`  ${file.file}: ${formatMetric(file.metrics)}`);
		}
	}

	const failures = results.flatMap(result => result.failures.map(failure => `${result.suite.name}: ${failure}`));
	if (failures.length > 0) {
		console.error('\nFocused coverage threshold failures:');
		for (const failure of failures) {
			console.error(`  - ${failure}`);
		}
		process.exitCode = 1;
		return;
	}

	console.log('\nAll focused coverage thresholds passed.');
}

try {
	main();
} catch (error) {
	console.error(error instanceof Error ? error.message : String(error));
	process.exitCode = 1;
}