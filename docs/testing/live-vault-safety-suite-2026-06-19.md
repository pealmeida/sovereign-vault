# Live Vault Safety E2E Suite - 2026-06-19

This plan validates Sovereign Vault as a local-first encrypted vault when an AI
agent uses the MCP stdio proxy and a human user approves or denies operations
through the desktop app. All payloads in this suite are synthetic and safe to
expose in logs.

## Scope

- Desktop app: `target/release/sovereign-vault-desktop.exe`
- Agent path: `target/release/sovereign-vault.exe mcp-stdio`
- User interaction path: Windows Computer Use against the desktop window
- Vault root: `%APPDATA%\com.sovereignvault.desktop\sovereign-vault`
- Modes under test: `DIRECT`, `APPROVAL`, `OTP`, `ANONYMIZED`, `ZKP`, `NATIVE`
- File extensions under test: `.env`, `.json`, `.md`, `.pem`, `.csv`, `.txt`

## Safety Rules

- Never use real credentials, personal data, recovery phrases, or production
  files.
- Use unique fake markers per run so filesystem scans can distinguish test data.
- Do not print or copy the recovery phrase into external logs or chat.
- For storage checks, scan the vault root for both raw fake markers and their
  base64 encodings.
- Treat unsupported modes as validated outcomes when the app returns an explicit
  live-MCP error before storing data.

## Expected Mode Behavior

| Mode | Create container | Write | Read | List files | Expected protection |
|---|---:|---:|---:|---:|---|
| `DIRECT` | Approval prompt | Auto | Auto | Auto | Encrypted at rest, no per-file consent |
| `APPROVAL` | Approval prompt | Approval prompt | Approval prompt | Approval prompt | Human click consent per protected operation |
| `OTP` | OTP challenge | OTP challenge | OTP challenge | OTP challenge | Desktop shows code, agent resends code |
| `ANONYMIZED` | Approval prompt | Auto | Auto | Auto | Reads mask supported PII before returning |
| `ZKP` | Explicit not implemented error | N/A | N/A | N/A | No live MCP storage path yet |
| `NATIVE` | Explicit not implemented error | N/A | N/A | N/A | No live MCP storage path yet |

## Test Data

Use one run prefix: `codex-suite-<timestamp>`.

| File | Extension | Payload purpose |
|---|---|---|
| `app.env` | `.env` | Fake API key and database URL |
| `settings.json` | `.json` | Structured fake service config |
| `runbook.md` | `.md` | Markdown operational notes |
| `public-key.pem` | `.pem` | Fake PEM-like public material |
| `inventory.csv` | `.csv` | Tabular fake inventory |
| `contact.txt` | `.txt` | PII-shaped fake text for anonymization |

## Test Cases

### TC-00: Preconditions

1. Launch the rebuilt desktop executable.
2. Unlock the vault with OS Keychain.
3. Verify `http://127.0.0.1:9943/health` returns `ok: true`.
4. Start MCP requests only through `sovereign-vault.exe mcp-stdio`.

Expected: desktop is unlocked and the MCP proxy can pair.

### TC-01: DIRECT Exact Round Trip

1. Create `codex-suite-<timestamp>-direct` with mode `DIRECT`.
2. Approve the create prompt.
3. Write `.env`, `.json`, `.md`, and `.pem` files.
4. Read each file back.
5. List files in the container.

Expected: writes, reads, and list complete without additional prompts. Returned
base64 decodes exactly to the original fake payloads.

### TC-02: APPROVAL Human Gate

1. Create `codex-suite-<timestamp>-approval` with mode `APPROVAL`.
2. Approve the create prompt.
3. Write `settings.json` and `inventory.csv`, approving each write.
4. Read both files, approving each read.
5. List files, approving the list.

Expected: every protected operation raises an approval modal with the action,
container, and file when applicable. Returned content matches the fake payloads.

### TC-03: OTP Challenge Response

1. Create `codex-suite-<timestamp>-otp` with mode `OTP`.
2. Capture the desktop OTP code and resend the create request with `otp`.
3. Write `contact.txt`, using the desktop OTP challenge response.
4. Read `contact.txt`, using a new desktop OTP challenge response.
5. Replay the last OTP for the same read request.

Expected: create/write/read succeed only after the current OTP is supplied.
Replay of a consumed OTP is rejected.

### TC-04: ANONYMIZED Masked Read

1. Create `codex-suite-<timestamp>-anon` with mode `ANONYMIZED`.
2. Approve the create prompt.
3. Write `contact.txt` and `settings.json` containing fake email, phone, and
   token-shaped values.
4. Read both files.
5. Compare returned content with original payloads.

Expected: read responses are returned without approval prompts, but supported
PII-shaped spans are masked before crossing the MCP boundary. The vault still
stores encrypted `.svault` files at rest.

### TC-05: Unsupported Live Modes

1. Attempt to create `codex-suite-<timestamp>-zkp` with mode `ZKP`.
2. Attempt to create `codex-suite-<timestamp>-native` with mode `NATIVE`.

Expected: both return explicit not-implemented errors before storing test data.

### TC-06: Encryption at Rest and Audit Hygiene

1. Scan the vault root for each raw fake marker.
2. Scan the vault root for each fake payload's base64 encoding.
3. Confirm files on disk use `.svault`.
4. Inspect recent audit log entries for hashed container/file identifiers.

Expected: no raw fake secret or reversible base64 payload appears under the
vault root. Stored file bodies are encrypted `.svault` blobs. Audit entries
avoid plaintext container and file names for protected MCP operations.

### TC-07: Lock Boundary

1. Lock the vault from the desktop.
2. Attempt an MCP read from a created test container.
3. Unlock with OS Keychain.
4. Repeat the read and complete the required approval or OTP flow.

Expected: locked vault blocks MCP pairing/read. After unlock, data remains
available only through the configured mode gate.

## Live Run Results

Status: completed with defects.

Run ID: `codex-suite-20260619181826`

| Case | Status | Notes |
|---|---|---|
| TC-00 | Pass | Desktop was running and unlocked at start. `/health` returned `ok: true`. |
| TC-01 | Pass | `DIRECT` container created after create approval. `.env`, `.json`, `.md`, `.pem` wrote and read back exactly. No per-file prompts after creation. |
| TC-02 | Pass | `APPROVAL` container used `.json` and `.csv`. Six prompts appeared and were approved: create, two writes, two reads, one list. Read-back matched. |
| TC-03 | Pass | `OTP` container create/write/read all required desktop codes. Read-back matched. Reusing a consumed OTP returned a fresh `otp_required` challenge. |
| TC-04 | Partial | `ANONYMIZED` container created after approval. `.txt` read masked fake email and `+1 202 555 0101` phone. `.json` read masked fake email but did not mask dashed phone `202-555-0199`. |
| TC-05 | Pass | `ZKP` and `NATIVE` create attempts returned explicit `not implemented for live MCP access` errors and did not create containers. |
| TC-06 | Pass | Vault-root scan found 0 hits for raw fake markers and 0 hits for base64 encodings of all known fake payloads. Test files were stored as `.svault`. |
| TC-07 | Fail | Locking blocked MCP pairing as expected, but OS Keychain unlock then failed repeatedly with `AEAD operation failed: aead::Error`, including after a full app/WebView process-tree restart. |

## Containers Created

| Container | Mode | Files |
|---|---|---|
| `codex-suite-20260619181826-direct` | `DIRECT` | `app.env.svault`, `settings.json.svault`, `runbook.md.svault`, `public-key.pem.svault` |
| `codex-suite-20260619181826-approval` | `APPROVAL` | `settings.json.svault`, `inventory.csv.svault` |
| `codex-suite-20260619181826-otp` | `OTP` | `contact.txt.svault` |
| `codex-suite-20260619181826-anon` | `ANONYMIZED` | `contact.txt.svault`, `settings.json.svault` |

No `ZKP` or `NATIVE` containers were created because live MCP rejected those modes
before storage.

## Observed Mode Behavior

| Mode | Result |
|---|---|
| `DIRECT` | Works for exact read/write/list round trips after approved creation. |
| `APPROVAL` | Works and shows action-specific prompts with container/file context. |
| `OTP` | Works for create/write/read; codes are display-only on desktop and single-use from the agent side. |
| `ANONYMIZED` | Works as an MCP read filter, but masking coverage is incomplete for dashed phone formats. |
| `ZKP` | Explicitly unsupported in live MCP. |
| `NATIVE` | Explicitly unsupported in live MCP. |

## Findings

1. `TC-07` is a blocking reliability defect for OS Keychain vaults. After a
   successful lock, OS Keychain unlock can fail with `AEAD operation failed:
   aead::Error`. In this run, restarting the desktop app and its WebView child
   processes did not recover the vault.
2. `ANONYMIZED` masking is not comprehensive. It redacted email addresses and
   `+1 202 555 0101`, but not the dashed phone value `202-555-0199` inside JSON.
3. `ZKP` and `NATIVE` are still visible in the schema/UI but are live-MCP stubs.
   The explicit error is clear, but the create UI should probably label them as
   unavailable until implemented.
4. The OTP modal code is visible on screen but not exposed in the accessibility
   tree. That is acceptable for secrecy, but it means automated accessibility
   tests need screenshot/OCR or manual visual capture for OTP workflows.

## Residual Risks To Track

- The app was left locked at the end of this run because OS Keychain unlock is
  failing with `AEAD operation failed: aead::Error`.
- The test containers contain fake data only, but they remain in the vault root
  as encrypted `.svault` files for follow-up inspection.
- Any local agent logs generated during tests can contain fake plaintext by
  design; remove temporary harness logs after assertions complete.
