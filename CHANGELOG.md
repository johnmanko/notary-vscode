# Change Log

All notable changes to the `notary` extension will be documented in this file.

See [johnmanko/notary-vscode/CHANGELOG.md](https://github.com/johnmanko/notary-vscode/blob/master/CHANGELOG.md) for most current log.

## 1.1.0

### Added

- Multi-source key support with create and edit flows for Manual, OIDC/JWKS URL, and direct JWKS JSON keys.
- JWKS JSON key entry and editing with grouped key claims and derived public key display.
- Key descriptions (up to 50 characters) across key creation, storage, and sidebar display.

### Changed

- JWT signature validation behavior is unified across all key sources (manual, URL, JWKS JSON).
- JWT key-selection behavior now uses JWT `kid` matching first, with manual override from the JWT Viewer key selector.
- Manual key modeling no longer stores PEM as a `key` claim in generated key JSON.
- Key details panel UX refinements:
  - Read-only values are displayed as non-input read-only blocks.
  - Public key read-only displays use display blocks instead of disabled textareas.
  - Raw JSON wrapping and container behavior improved.
  - Save button and key panel title behavior refined.
- Sidebar UX and styling refinements:
  - Updated action ordering and alignment.
  - Source badges styled to match key details badge colors.
  - Delete action button styled to match key details danger treatment.
- README and screenshots updated for JWKS JSON workflows and current UI/validation behavior.

### Fixed

- Sidebar state synchronization when switching activity bar views.
- Expanded and updated tests covering key selection logic, key model behavior, and UI-label/flow behavior.

### Removed

- `preferredKeyRef` from the active key model and persisted key-set payloads.

## 1.0.0

- Initial release