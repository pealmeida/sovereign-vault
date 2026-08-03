# UI / Desktop Test Cases — detailed

> **Platform note:** the NSIS/`%LOCALAPPDATA%` install steps are Windows-specific;
> the macOS build installs a `.app`/DMG (see the repo README).

Companion to `e2e-test-plan.md`. Concrete, repeatable desktop-app cases driven through the installed window (manually or via computer-use). Each case: precondition → steps → expected. Items marked **VERIFIED 2026-05-25** were exercised live in the installed prod build.

## Build & launch (prerequisite)

- **UI-BUILD-1** Build with `cargo tauri build` (NOT plain `cargo build` — that yields a dev-mode exe that shows *"can't reach localhost:1420"*). **VERIFIED:** plain build reproduced the blank/Edge-error page; the `cargo tauri build` bundle renders correctly. ✅
- **UI-BUILD-2** Install the per-user NSIS (`…_x64-setup.exe /S`) → registers `%LOCALAPPDATA%\Sovereign Vault\` + Start-menu shortcut, no UAC. **VERIFIED.** ✅
- **UI-BUILD-3** For computer-use automation the app must be installed (an unregistered `target\debug` exe can't be granted). **VERIFIED** (grant failed for dev exe, succeeded post-install). ✅

## Bootstrap (fresh vault)

- **UI-BOOT-1** First launch with no vault → "Initialise" flow; choose **OS keychain** → random KEK stored, keyring created.
- **UI-BOOT-2** Choose **Passphrase** → salt written, KEK derived; recovery phrase shown **once**; copy works.
- **UI-BOOT-3** Re-init when a vault exists → blocked ("already initialised").

## Unlock

- **UI-UNL-1** PASSPHRASE tab → correct passphrase unlocks; wrong → error, stays locked.
- **UI-UNL-2** OS KEYCHAIN tab → "no passphrase entry needed"; UNLOCK opens the vault. **VERIFIED** (toast "Vault unlocked"). ✅
- **UI-UNL-3** RECOVERY tab → 24-word phrase unlocks; post-rotation only the **new** phrase works.
- **UI-UNL-4** Legacy (pre-keyring) vault opens on first unlock via migration, data intact. **VERIFIED** — existing `finance`/`mcp-demo` opened; `note1.txt` decrypted to "First file written via MCP. Hello from Claude Code." ✅

## Vault — containers

- **UI-VLT-1** New vault → name + description + mode (DIRECT/APPROVAL/OTP/ANONYMIZED/ZKP/NATIVE) → CREATE → toast + row appears. **VERIFIED** (`claude-test` DIRECT). ✅
- **UI-VLT-2** Mode badge renders per container (OTP/DIRECT). **VERIFIED.** ✅
- **UI-VLT-3** Invalid name (`..`, slash, >64, leading dot) → rejected.
- **UI-VLT-4** Expand row → "Open in Files" / "Delete". **VERIFIED.** ✅
- **UI-VLT-5** Delete container → confirm → removed (irreversible; verify warning).

## Files

- **UI-FIL-1** Files page lists files per container with mode, size, modified date. **VERIFIED** (mcp-demo: codex-smoke.txt, note1.txt, note2.json). ✅
- **UI-FIL-2** Eye/preview → decrypts and shows content inline (text/PDF/image/etc.). **VERIFIED** (note1.txt). ✅
- **UI-FIL-3** Browse/drop import → file sealed into the selected container. *Native open-dialog; verify import of a fake `webapp.env`.*
- **UI-FIL-4** Download → writes decrypted bytes out (confirm prompt for the save).
- **UI-FIL-5** Delete file → removed from registry.

## Settings — identity & key management

- **UI-SET-1** Custody panel shows mode, OS-keychain entry, recovery bundle, **Key hierarchy: Keyring (rotatable)**. **VERIFIED.** ✅
- **UI-SET-2** Show recovery phrase (post-init) reveals + copies.
- **UI-SET-3** **Change passphrase** (passphrase custody) → data intact, recovery phrase unchanged, old passphrase rejected on next unlock.
- **UI-SET-4** **Rotate key** → re-encrypts files, reveals a **new** recovery phrase; old phrase stops working. *Destructive to old recovery — confirm copy first.*

## Settings — MCP & agents

- **UI-MCP-1** MCP server shows **RUNNING**, ws endpoint, tool chips (encrypt/decrypt/sign/verify present). **VERIFIED.** ✅
- **UI-MCP-2** Copy Claude Desktop / Cursor / Continue.dev config buttons produce valid config.
- **UI-AGT-1** Agents lists **Default** with Revoke. **VERIFIED.** ✅
- **UI-AGT-2** New agent → one-time token shown **once** + Copy. **VERIFIED** (`claude-code` minted). ✅
- **UI-AGT-3** Revoke agent → its token no longer pairs.

## Settings — transit / signing / broker

- **UI-TR-1** Create transit key → appears as `name vN`; key bytes never displayed. **VERIFIED** (`demo-key v1`). ✅
- **UI-SI-1** Create signing key → public key copyable; private never shown.
- **UI-BR-1** Brokered secrets: with broker off, shows **"Brokering is disabled. Set SV_ENABLE_BROKER…"**. **VERIFIED.** ✅
- **UI-BR-2** With `SV_ENABLE_BROKER=1`: create a brokered secret with host allowlist + Bearer injection.

## Approvals (human-in-the-loop)

- **UI-APP-1** An approval-gated agent MCP call raises a desktop prompt; Approve → call proceeds; Deny → call fails. **VERIFIED LIVE 2026-05-25:** background `vault.encrypt` raised the global modal on the **Settings** page; APPROVE resolved the call. ✅
- **UI-APP-2** OTP container → prompt requires the displayed one-time code; wrong code rejected.
- **UI-APP-3** Settings → *Pending requests* lists in-flight approvals; "Open audit folder" works.
  > **VERIFIED LIVE 2026-05-25 (commit `87c8ff8`):** confirmed on the **Settings** page (a non-Files page) — the global Approval modal appeared for a background `vault.encrypt`, and APPROVE resolved the agent call. The event-name + global-host fix works end-to-end. ✅

## Lock / lifecycle

- **UI-LCK-1** Lock vault → returns to unlock screen; MCP/HTTP servers stop (subsequent proxy pair fails until re-unlock).
- **UI-LCK-2** Relaunch → unlock → existing agents/keys/containers persist.

## Known UI findings (track to closure)

1. **Approval modal surfacing** — FIXED + VERIFIED LIVE 2026-05-25 (`87c8ff8`: event-name + global modal host).
2. **Leading-dot filenames** — FIXED + VERIFIED LIVE 2026-05-25 (`is_valid_file_name` now allows `.env`; wrote/listed/previewed `.env` in `claude-test`).
3. **Broker UI** lacks multi-allow-entry editing, custom-header injection, and key rotate/delete actions.
4. **Native file dialog** import not yet automated in computer-use runs (manual step).
