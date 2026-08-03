# UI/UX Redesign — Three-Page Layout (Vault / Files / Settings)

- **Date:** 2026-05-22
- **Owner:** pealmeida
- **Status:** Draft for review (rev 2 — corrected reference)
- **Scope:** `ui/` (Svelte 5 + Vite) — single-page `App.svelte` → three-view shell
- **Visual reference:** `<USER_HOME>\Code\agentic-sovereign-ecosystem\apps\sovereign-vault` (the older Svelte 5 sovereign-vault frontend)
- **Target:** Tauri 2 desktop app, Windows-first

## 1. Goals

1. Replace the 859-line monolithic `ui/src/App.svelte` with a three-view shell: **Vault**, **Files**, **Settings**.
2. Port the **exact design language** (colors, type, panel-card system, sidebar, top bar, chips, table) from `agentic-sovereign-ecosystem/apps/sovereign-vault` to our Svelte 5 + Tauri 2 frontend.
3. Preserve **every** existing feature of the current sovereign-vault: init/unlock/recovery, 6 container modes, file CRUD, MCP status + Claude/Cursor/Continue config snippets, desktop approval flow.
4. Refactor business logic out of `App.svelte` into typed stores + a thin Tauri client. Pages stay presentational.

## 2. Non-goals

- No mobile / Tauri-Mobile target.
- No light theme (the reference is dark-only; `color-scheme: dark`).
- No new MCP tools or Tauri commands.
- No bottom-bar mobile responsive variant beyond what's free from the source CSS.
- No Mission Control bridge / browser preview mode — the source has it; we ignore it (Tauri-only runtime).
- No standalone Dashboard, Agents, Policy, Secrets, or MCP-Access pages — the source has them in its sidebar; we drop them to keep the spec's 3-page scope. MCP content folds into Settings.

## 3. Feature inventory (what must survive)

From `ui/src/App.svelte` and `apps/desktop/src-tauri/src/lib.rs` (16 `#[tauri::command]` handlers):

### Vault lifecycle
- `vault_status`, `vault_init`, `vault_unlock`, `vault_unlock_recovery`, `vault_lock`

### Container management
- `vault_list_containers`, `vault_create_container`, `vault_delete_container`
- Modes: `DIRECT | APPROVAL | OTP | ANONYMIZED | ZKP | NATIVE`

### File operations
- `vault_list_files`, `vault_write_file`, `vault_read_file`, `vault_delete_file`

### MCP & approvals
- `mcp_status`
- `approval_respond` (desktop approval flow for `APPROVAL` and `OTP` mode containers)
- Claude Desktop / Cursor / Continue.dev config snippets (currently in `App.svelte` `claudeConfigSnippet()`)

### Misc
- `app_version`
- Recovery phrase reveal/copy

## 4. Page mapping

| Page         | Route                | Content                                                                                                                                  |
| ------------ | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **Vault**    | `/` and `/vault`     | Header `Agent storage / Secure data categories` (matches source's `viewTitle('vault')`). Container grid using the source's `panel-card` + `vault-row` pattern with mode pills. When locked: `LockedCard` overlay. |
| **Files**    | `/files/:container?` | Header `Vault files / Encrypted file registry`. Filter-chip row over the file table. Uses the source's `.vault-table` styling. |
| **Settings** | `/settings`          | Header `Preferences / Storage and runtime`. Two-column `.settings-grid`: left = Identity & Recovery + About; right = MCP Server + Approvals. |

### Page details

**Vault (locked state):**
- Centered `panel-card` (max-width 520px) with three tabbed sub-flows: `OS Keychain`, `Passphrase`, `Recovery phrase`.
- Init flow when `status.initialized === false`; unlock flow otherwise.
- After init: `RecoveryPhraseBanner` — full-width card with the 24-word phrase in `.font-mono`, `CopyButton`, "I've stored it safely" primary button to dismiss.

**Vault (unlocked state):**
- `panel-header` with eyebrow `Vault layout` + title `Vaults & folders` (mirroring source `VaultPanel.svelte`).
- `vault-list` of `vault-row` cards. Each row collapses/expands; summary shows: chevron · folder icon · `vault-meta` (name + path) · file count · `mode-pill`.
- Expanded row reveals first 3 files as `entry-row` items + an `Open in Explorer` ghost button.
- Empty state uses source's `.empty-state` class.
- New-container call-to-action: `+ NEW VAULT` ghost button in `panel-header` (matches source's `TopBar.svelte` `newVault()` flow — moved to header instead of TopBar since we keep TopBar minimal).

**Files:**
- `panel-card` with `panel-header` (eyebrow `Imported objects` + title `Encrypted file registry`).
- Filter-chip row: container names + an `ALL` chip. Mirrors source's `activeMode` filter pattern at `FilesPanel.svelte`.
- `.table-shell` → `.vault-table` with columns: `Item · Mode · Size · Modified · ⋮`.
- Row `item-cell` shows file icon + name + container path; `mode-pill` in security column.
- Per-row actions: `Open` (preview via `FileViewerModal`), `Download` (`@tauri-apps/plugin-dialog` save), `Delete` (confirm).
- Drag-and-drop overlay on the table for upload, plus an `Upload` ghost button in `panel-header`.
- Approval banner: a sticky `.notice-banner` above the table when a MCP approval request targets the current container.

**Settings:**
- Two `panel-card` columns inside `.settings-grid`. Mirrors source `SettingsPanel.svelte` grid pattern.
- **Left column:**
  - `Identity & Recovery` — current custody mode, "Show recovery phrase" (re-auth required), "Re-key from recovery phrase" (advanced).
  - `About` — `app_version`, license, build hash, repo link.
- **Right column:**
  - `MCP Server` — status pill (running / port / pid), tool list (5 tools), `Copy Claude Desktop config`, `Copy Cursor config`, `Copy Continue.dev config`, all using source's `CopyButton` pattern.
  - `Approvals` — pending queue (empty in normal state) + `Open audit folder` ghost button.

## 5. Architecture

```
ui/src/
  main.ts
  App.svelte                       # <SidebarNav /> + <main class="main-shell"><TopBar /><Router /></main>
  app.css                          # ported from source: tokens + .app-shell + .sidebar + .panel-card + .vault-table + chips
  lib/
    tauri.ts                       # typed invoke<T>(cmd, args) wrapper
    types.ts                       # VaultStatus, ContainerInfo, FileInfo, McpStatus, SecurityMode, VaultView ...
    formatters.ts                  # bytes, dates, mode-class mapper
  stores/
    vault.ts                       # $state status, init/unlock/lock/recover actions
    containers.ts                  # $state list, create/delete/refresh
    files.ts                       # $state per-container cache, read/write/delete/upload
    mcp.ts                         # $state status + config snippets (claude, cursor, continue)
    approvals.ts                   # $state pending queue, respond()
    toast.ts                       # globalNotice / globalError (mirrors source App.svelte)
  components/
    SidebarNav.svelte              # PORT of source SidebarNav, items trimmed to Vault/Files/Settings
    TopBar.svelte                  # PORT of source TopBar, search + refresh + open-root + lock
    LockedCard.svelte              # init/unlock/recovery tabs (uses .panel-card)
    RecoveryPhraseBanner.svelte
    ContainerRow.svelte            # PORT of vault-row pattern from VaultPanel
    NewContainerModal.svelte
    FileRow.svelte                 # vault-table tr renderer
    UploadDropzone.svelte
    ApprovalBanner.svelte
    FileViewerModal.svelte         # PORT of source FileViewerModal
    ApprovalModal.svelte           # PORT of source ApprovalModal
    OtpModal.svelte                # PORT of source OtpModal
    CopyButton.svelte
    ModePill.svelte                # encapsulates mode-direct / mode-approval / mode-otp / mode-anon / mode-zkp / mode-native
    ContextMenu.svelte             # PORT of source lib/ContextMenu.svelte
    Toast.svelte                   # globalNotice + globalError renderer
  pages/
    VaultPage.svelte
    FilesPage.svelte
    SettingsPage.svelte
```

### State pattern
- Svelte 5 runes (`$state`, `$derived`, `$effect`).
- Each store exports `{ state, actions }`. Pages consume `state`; components emit events.
- `lib/tauri.ts` is the only file that calls `invoke`. Stores depend on it; pages/components depend on stores.
- `globalNotice` + `globalError` lifted to a `toast` store (matches source's `App.svelte` pattern).

### Routing
- `svelte-spa-router@^4` (hash routes — `#/vault`, `#/files`, `#/files/:container`, `#/settings`).
- Locked-state guard: if `vault.status.locked`, the route content slot is replaced by `<LockedCard />`. Sidebar buttons render but are disabled.
- *Note:* the source uses a simple reactive `activeView` switch with `localStorage`. We deliberately chose a router so deep-links and back/forward work, per earlier brainstorming decision.

## 6. Visual design (ported verbatim from source `app.css`)

### Color tokens

```css
:root {
  color-scheme: dark;

  --bg:             #09111f;
  --bg-elevated:    #101a2c;
  --surface:        rgba(14, 24, 40, 0.84);
  --surface-strong: rgba(18, 31, 51, 0.98);
  --surface-soft:   rgba(14, 24, 40, 0.68);
  --border:         rgba(111, 144, 191, 0.24);
  --border-strong:  rgba(98, 242, 255, 0.34);
  --text:           #edf5ff;
  --muted:          #8fa5c5;
  --accent:         #62f2ff;     /* cyan/aqua — brand */
  --accent-soft:    rgba(98, 242, 255, 0.12);
  --green:          #42d392;
  --yellow:         #f3c969;
  --red:            #ff6f7c;
  --purple:         #98a4ff;
  --shadow:         0 18px 50px rgba(0, 0, 0, 0.35);
  --radius:         8px;
  --radius-sm:      6px;
}

body {
  background:
    radial-gradient(circle at top left, rgba(98, 242, 255, 0.12), transparent 30%),
    radial-gradient(circle at bottom right, rgba(152, 164, 255, 0.09), transparent 30%),
    linear-gradient(180deg, #07101c 0%, #09111f 100%);
}

body::before {
  /* faint grid overlay */
  content: '';
  position: fixed; inset: 0; pointer-events: none;
  background-image:
    linear-gradient(to right, rgba(143, 165, 197, 0.06) 1px, transparent 1px),
    linear-gradient(to bottom, rgba(143, 165, 197, 0.06) 1px, transparent 1px);
}
```

### Mode pills (color-coded by security mode)

```css
.mode-direct   { background: rgba(80,160,255,0.15);  color: #6cb2ff; }
.mode-approval { background: rgba(255,180,80,0.15);  color: #ffc06d; }
.mode-otp      { background: rgba(120,255,160,0.15); color: #6dffae; }
.mode-anon     { background: rgba(255,120,200,0.15); color: #ff8ad0; }
.mode-zkp      { background: rgba(180,120,255,0.15); color: #c08aff; }
.mode-native   { background: rgba(98,242,255,0.15);  color: var(--accent); }
```

### Typography

- `--font-display: 'Space Grotesk', 'Aptos', 'Segoe UI Variable', sans-serif`
- `--font-body:    'Aptos', 'Segoe UI Variable', 'Trebuchet MS', sans-serif`
- `--font-mono:    'Fira Mono', 'Consolas', monospace`
- Loaded via `@fontsource/space-grotesk` (400/500/700) + `@fontsource/fira-mono` (400/500).

### Layout primitives (verbatim class names)

- `.app-shell` — `display: grid; grid-template-columns: 280px minmax(0, 1fr); min-height: 100vh`
- `.sidebar` — `flex-direction: column; gap: 1.25rem; padding: 1.5rem; border-right: 1px solid var(--border); background: rgba(7, 13, 24, 0.9); backdrop-filter: blur(18px)`
- `.brand-panel` — logo + title block with gradient bg
- `.runtime-chip` / `.mode-chip` / `.timestamp-chip` / `.filter-chip` — rounded-full mono uppercase chips
- `.nav-list` — vertical button column
- `.nav-button` — full-width button, active state lights `--border-strong` + `--accent-soft`
- `.import-button` / `.primary-button` — gradient `linear-gradient(135deg, rgba(98,242,255,0.22), rgba(152,164,255,0.18))`
- `.ghost-button` — outlined neutral
- `.main-shell` — `padding: 1.5rem; gap: 1.5rem; flex-direction: column`
- `.topbar` — `grid-template-columns: minmax(0,1fr) minmax(320px, 520px); gap: 1rem`
- `.search-shell` — full-bleed search with leading icon
- `.panel-card` — main content card (shadow + border + backdrop blur)
- `.panel-header` — eyebrow + title + actions
- `.vault-list` / `.vault-row` / `.vault-summary` / `.vault-contents` / `.entry-row` — vault rows
- `.table-shell` / `.vault-table` — file table
- `.empty-state` — empty state block
- `.toast.toast-success` / `.toast.toast-error` — top-fixed transient banners
- `.modal-shell` — modal container (for ApprovalModal / OtpModal / FileViewerModal / NewContainerModal)

The full `app.css` (~16 KB) is copied verbatim from the source, with these surgical edits:
1. Remove unused `.runtime-bar` Mission-Control browser-mode states (we're Tauri-only).
2. Remove `.wizard-grid`, `.import-draft-head`, `.file-settings-grid`, `.ops-strip` (Import Wizard not in scope).
3. Remove `.dashboard-columns`, `.metric-grid`, `.metric-card`, `.code-card-header` (Dashboard not in scope).
4. Keep all responsive `@media` queries — sidebar collapses to horizontal row at <1024px and bottom-bar at <740px, matching source.

### Icons

`lucide-svelte` — the source uses these exact icons. Reusing the same imports gives pixel parity:
`Activity, FolderLock, Files, Settings2, Cable, Bot, KeyRound, Plus, ShieldCheck, Vault, Search, RefreshCcw, FolderOpen, ShieldEllipsis, ExternalLink, Save, RotateCcw, Lock, Unlock, Eye, EyeOff, Copy, Trash2, Download, Upload, ChevronDown, ChevronRight, X`.

## 7. Dependencies to add (`ui/package.json`)

```jsonc
{
  "dependencies": {
    "@fontsource/space-grotesk": "^5.0.0",
    "@fontsource/fira-mono": "^5.0.0",
    "lucide-svelte": "^0.460.0",
    "svelte-spa-router": "^4.0.1"
  }
}
```

## 8. Migration plan (incremental commits)

1. **Scaffolding** — add deps, create folder skeleton, save current `App.svelte` as `App.legacy.svelte` for parity reference, replace `App.svelte` with empty shell.
2. **Port `app.css`** — drop in tokens + layout + chips + cards + table, prune Dashboard/Wizard/Mission-Control rules.
3. **Extract stores** — pull every `invoke<T>(...)` from `App.legacy.svelte` into `stores/*.ts`. Build `lib/tauri.ts`. Verify by mounting a debug page that prints `JSON.stringify(state)`.
4. **SidebarNav + TopBar** — port from source, trim sidebar items to Vault/Files/Settings, drop browser-mode branch in TopBar.
5. **VaultPage** — `LockedCard`, `RecoveryPhraseBanner`, `ContainerRow` (vault-row pattern), `NewContainerModal`, `ContextMenu`.
6. **FilesPage** — filter-chip row, `vault-table`, `FileRow`, `UploadDropzone`, `ApprovalBanner`, `FileViewerModal`, `ApprovalModal`, `OtpModal`.
7. **SettingsPage** — Identity & Recovery card, About card, MCP Server card, Approvals card.
8. **Delete `App.legacy.svelte`**; final `pnpm check` + `cargo tauri dev` smoke.

Each commit must `pnpm check` clean.

## 9. Manual smoke-test checklist

- [ ] Fresh launch on clean profile → init with Passphrase → recovery phrase shows in `RecoveryPhraseBanner` → copy works → "I've stored it safely" dismisses.
- [ ] Init with OS Keychain → restart app → still unlocked.
- [ ] Wrong passphrase → `toast-error` banner, no JSON blob.
- [ ] Recovery phrase unlock path works.
- [ ] Create container in each of 6 modes — `mode-pill` colors match the token map.
- [ ] Delete container with files — confirm modal blocks → success toast.
- [ ] Sidebar Vault → Files navigation preserves selected container (URL param works).
- [ ] Drag-drop upload + button upload both succeed.
- [ ] `FileViewerModal` previews text + JSON under 256 KB.
- [ ] Download writes correct bytes (hash check via `certutil -hashfile`).
- [ ] MCP approval from Claude Code → `ApprovalBanner` on Files page → Approve and Deny both work via `approval_respond`.
- [ ] OTP container access triggers `OtpModal`.
- [ ] Settings → Copy Claude Desktop config → paste validates as JSON.
- [ ] Settings → Open audit folder reveals the right path.
- [ ] Lock from TopBar → routes to `LockedCard`, sidebar buttons disabled.
- [ ] Responsive: 1024px width collapses sidebar to horizontal row, 740px to bottom strip (free from source CSS).
- [ ] `cargo tauri build` produces a working installer.

## 10. Risks & trade-offs

| Risk | Mitigation |
| --- | --- |
| 859-line legacy port misses an edge case | Keep `App.legacy.svelte` until step 8; smoke-test checklist covers every Tauri command. |
| `app.css` references classes the legacy never used (e.g. `.metric-grid`) | Step 2 explicitly prunes Dashboard/Wizard CSS. svelte-check warns on unknown classes only inside `<style>` scoped sections, so global `app.css` is loose — accept light dead-CSS risk and clean as we go. |
| Source uses `localStorage` for state persistence (settings, last view); we don't currently | Out of scope. Stores reset on app launch. Add localStorage later if needed. |
| Visual drift from source | Side-by-side screenshot diff per page before merge. |
| Font fetching (`@fontsource`) adds ~200 KB to bundle | Accept — matches source. Fonts ship in the app bundle, no runtime network. |
| Hash routing makes the URL bar look ugly (`#/files/foo`) | Tauri webview doesn't show a URL bar — irrelevant. |

## 11. Open questions

1. **File preview byte limit** — pick 256 KB? (No precedent in source.)
2. **Settings persistence** — should we add `localStorage` for theme/last-view like the source does? Spec assumes **no** for v1.
3. **MCP config snippet formats** — keep the three (Claude/Cursor/Continue) shown in current `App.svelte`, or trim to just Claude Desktop?

## 12. Out-of-scope follow-ups

- Dashboard/Agents/Policy/Secrets/MCP-Access pages (source has them; user explicitly scoped to 3 pages).
- Import Wizard flow (source has it; replaced by simple `Upload` button + drag-drop in v1).
- localStorage state persistence.
- Multi-select + bulk delete in Files.
- Search across containers (source has a global search; we keep TopBar search but only filter the current page).
- Sortable / filterable file table columns beyond mode filter.
- Keyboard shortcuts.
- Mission Control bridge / browser preview mode.
