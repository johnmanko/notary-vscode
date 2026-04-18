const path = require('node:path');
const Module = require('node:module');

class MockUri {
	constructor(fsPath) {
		this.fsPath = fsPath;
		this.path = fsPath;
	}

	toString() {
		return this.fsPath;
	}

	static file(filePath) {
		return new MockUri(filePath);
	}

	static parse(value) {
		return new MockUri(value);
	}

	static joinPath(base, ...segments) {
		return new MockUri(path.join(base.fsPath, ...segments));
	}
}

const vscodeMock = {
	Uri: MockUri
};

const originalLoad = Module._load;
Module._load = function patchedLoad(request, parent, isMain) {
	if (request === 'vscode') {
		return vscodeMock;
	}
	return originalLoad.call(this, request, parent, isMain);
};