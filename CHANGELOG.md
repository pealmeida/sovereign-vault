# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/) once it reaches `0.1.0`.

> **Pre-alpha (`0.0.0`).** The on-disk format and APIs may change between commits
> without a version bump. Keep independent backups.

## [Unreleased]

### Fixed
- **Key rotation no longer orphans transit/signing/broker material.** Rotation
  re-wraps every transit key, signing seed, and broker secret forward to the new
  DEK instead of leaving them sealed under the retired one. Adds a regression
  test covering pre/post-rotation round-trips and survival across a fresh unlock.
- **Files page tab selection.** Clicking a container tab no longer reverts to the
  first container (the sync effect previously re-applied the route default over a
  manual selection).
- **Native delete confirmations.** Container/file deletes use the native Tauri
  dialog instead of the unreliable in-webview `window.confirm`.
- Dotenv files (`.env`, `*.env`, `.env.*`) now render as text in the file preview.

### Changed
- Identifier inputs (container/key/agent/broker names) disable
  autocapitalize/autocorrect/spellcheck so names aren't mangled.
- **Desktop bundle identifier** changed to `com.sovereignvault.desktop` (the old
  `com.sovereign-vault.app` collided with the macOS `.app` extension and blocked
  signing/notarization). ⚠️ This relocates the macOS app-data dir; an existing
  pre-alpha vault under the old identifier must be moved or recreated.
- Client secret loaders (Node/Python/shell) auto-discover the vault binary
  (repo build or `PATH`) instead of a hardcoded path; `SV_BIN` still overrides.
- Documentation made platform-neutral (macOS/Linux/Windows) and de-personalized.

### Added
- `docs/threat-model.md`, `docs/ARCHITECTURE.md`, and this `CHANGELOG.md`.
- `examples/` — ready-to-paste MCP client configs (Claude Desktop / Cursor /
  Continue) and a runnable `end-to-end.sh`.
- CI: supply-chain audit (`cargo audit` + `cargo deny`, weekly scheduled), an
  MSRV check, a release-compile step, least-privilege permissions, and run
  concurrency. `deny.toml`, `dependabot.yml`, issue/PR templates, `CODEOWNERS`.
- Workspace-wide `#![forbid(unsafe_code)]` lint.

### Security
- `.claude/settings.local.json` (local machine config) is no longer tracked.
