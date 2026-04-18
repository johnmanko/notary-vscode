# Test Suite Documentation

This directory contains comprehensive tests for the Notary JWT Viewer extension.

## Test Files

### Core Functionality Tests

#### `jwtDecoder.test.ts`
Tests for the JWT decoding utility module.
- **87 tests** covering:
  - Base64URL decoding with various padding scenarios
  - JWT format validation
  - JWT decoding with valid and invalid tokens
  - Token expiration checking
  - Not-before validation
  - Timestamp claim extraction

#### `jwtEdgeCases.test.ts`
Edge case and boundary condition tests for JWT decoder.
- **60+ tests** covering:
  - Very long strings and special characters
  - Invalid base64 and malformed JSON
  - Boundary timestamp values (Infinity, -Infinity, NaN)
  - Complex nested payloads
  - Whitespace handling

### Extension Tests

#### `extension.test.ts`
Core extension activation and command tests.
- **Tests cover:**
  - Extension activation
  - Command registration
  - Package.json metadata validation
  - Command availability
  - Extension lifecycle

#### `integration.test.ts`
Integration tests for complete workflows.
- **Tests cover:**
  - Extension lifecycle (activation, deactivation)
  - Command execution workflow
  - Multiple panel handling
  - Configuration validation
  - Webview functionality
  - Views and sidebar contributions
  - Error handling

### Utility Tests

#### `keyManagerSelection.test.ts`
Regression tests for key selection precedence and key-set editor data.
- **Tests cover:**
  - Explicit key override taking precedence over JWT `kid` match
  - `kid` match and preferred fallback behavior
  - URL/JWKS editor data preserving complete key-set metadata

#### `keyManagerOperations.test.ts`
Focused tests for `KeyManager` mutation and refresh behavior.
- **Tests cover:**
  - Manual, URL, and JWKS JSON add/update flows
  - Refresh behavior, refresh failures, and cached fallback behavior
  - CRUD operations and manager-level error handling

#### `webviewUtils.test.ts`
Tests for webview utility functions.
- **Tests cover:**
  - Nonce generation (uniqueness, format, length)
  - Asset URI creation for CSS and JS files
  - Webview URI formatting

#### `escapeUtils.test.ts`
Tests for HTML escaping utility.
- **20+ tests** covering:
  - Basic HTML character escaping (&, <, >, ")
  - XSS attack prevention
  - Edge cases (null, undefined, numbers, booleans)
  - Script tag handling
  - JWT and JSON string handling

## Running Tests

### Run all tests
\`\`\`bash
npm test
\`\`\`

### Run tests in watch mode
\`\`\`bash
npm run watch-tests
\`\`\`

### Compile tests only
\`\`\`bash
npm run compile-tests
\`\`\`

### Run focused coverage checks for Mocha suites
\`\`\`bash
npm run coverage:focused
\`\`\`

### Run focused coverage for a single suite
\`\`\`bash
npm run coverage:focused:file -- --suite keyManagement
\`\`\`

## Test Coverage

The test suite provides comprehensive coverage of:

1. **JWT Operations** (147+ tests)
   - Decoding and validation
   - Error handling
   - Edge cases and boundary conditions

2. **Extension Functionality** (40+ tests)
   - Activation and commands
   - Integration workflows
   - Configuration and metadata

3. **Utility Functions** (35+ tests)
   - HTML escaping and security
   - Webview utilities
   - Asset management

**Total: 225+ tests**

## Test Structure

Tests follow the Mocha testing framework with the following structure:
- `suite()` for grouping related tests
- `test()` for individual test cases
- `setup()` for test initialization (where needed)
- `assert` from Node.js for assertions

## Continuous Integration

Tests are designed to run in CI/CD pipelines and include:
- ✅ No external dependencies required
- ✅ Fast execution (typically < 1 minute)
- ✅ Deterministic results
- ✅ Clear error messages

## Focused Coverage

Focused coverage checks target the pure Mocha suites compiled into \`dist-test\` and enforce a 90% minimum for statements, branches, functions, and lines on the source files each suite is intended to cover.

The focused runner currently covers:
- \`escapeUtils.test.ts\`
- \`jwtDecoder.test.ts\`
- \`jwtEdgeCases.test.ts\`
- \`keyManagement.test.ts\`
- \`keyManagerSelection.test.ts\` and \`keyManagerOperations.test.ts\` together as the \`keyManager\` focused suite
- \`webviewUtils.test.ts\`

The VS Code extension-host suites \`extension.test.ts\` and \`integration.test.ts\` are intentionally not part of this runner because they execute under the VS Code test harness rather than plain Mocha.

## Writing New Tests

When adding new tests:
1. Place them in the appropriate test file or create a new one
2. Use descriptive test names that explain what is being tested
3. Follow the existing structure and naming conventions
4. Ensure tests are independent and don't rely on execution order
5. Add documentation comments for complex test scenarios

## Known Limitations

- Webview content testing is limited (requires VS Code environment)
- Some integration tests require VS Code extension host
- UI interactions are not directly testable (by design)
