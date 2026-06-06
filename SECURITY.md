# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| `main` (pre-1.0) | ⚠️ Pre-alpha; not yet externally audited. |

## Reporting a vulnerability

**Do not open a public GitHub issue.**

Please report via [GitHub Security Advisories](https://github.com/pealmeida/sovereign-vault/security/advisories/new) (private). If you cannot use that channel, contact a maintainer directly through their GitHub profile — do **not** include vulnerability details in any public space.

When reporting, include:

- A description of the issue and its impact.
- Steps to reproduce or proof-of-concept code.
- The affected version (commit hash if possible).
- Your contact for follow-up questions.

## Response targets

- Initial response: **within 7 days**.
- Triage + severity classification: **within 14 days**.
- Coordinated disclosure window: **90 days** from initial response, after which the issue may be made public regardless of fix status. We will negotiate extensions in good faith for complex cases.

## Scope

In scope:

- All crates under `crates/sv-*/`
- The Tauri desktop application under `apps/desktop/`
- The CLI under `apps/cli/`
- The MCP wire protocol implementation

Out of scope (not vulnerabilities):

- Issues in third-party dependencies that have no known fix and no mitigation we can apply.
- Social engineering of maintainers.
- Physical attacks on the user's machine.
- Issues requiring root/administrator privilege already obtained.

## Pre-1.0 caveat

This project has not yet been externally audited. The plan is to commission an external audit (Trail of Bits / Cure53 / NCC Group) during phase M7 of the v1.0 plan, before tagging `v1.0.0`. Until then, do not use Sovereign Vault to protect data whose loss or disclosure would be unacceptable.
