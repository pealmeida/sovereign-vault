# UI Redesign — Three-Page Layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the 860-line monolithic `ui/src/App.svelte` into a three-page shell (Vault / Files / Settings) using the visual design language from `agentic-sovereign-ecosystem/apps/sovereign-vault`.

**Architecture:** CSS grid shell (280px sidebar + content) with `svelte-spa-router` hash routing. Business logic extracted into six typed Svelte 5 rune stores (`.svelte.ts` files). `lib/tauri.ts` is the **only** file that calls `invoke`. Pages are presentational — they read store state and dispatch store actions.

**Tech Stack:** Svelte 5 runes, TypeScript, Vite 6, Tauri 2, svelte-spa-router@^4, lucide-svelte@^0.460, @fontsource/space-grotesk, @fontsource/fira-mono. npm (package-lock.json present).

**Reference sources:**
- Legacy design system: `C:\Users\pealm\Code\agentic-sovereign-ecosystem\apps\sovereign-vault\src\`
- Current app (parity reference): `ui/src/App.legacy.svelte` (created in Task 1)

---

## File Structure

**Create:**
```
ui/src/
  App.svelte                         (replace monolith — router shell)
  app.css                            (ported from legacy, 3 sections pruned)
  lib/
    types.ts                         (types extracted from App.svelte)
    tauri.ts                         (typed invoke wrapper — single invoke caller)
    formatters.ts                    (bytes, dates, modeClass)
  stores/
    vault.svelte.ts                  (status, init/unlock/lock/recover)
    containers.svelte.ts             (list, create/delete)
    files.svelte.ts                  (per-container cache, read/write/delete)
    mcp.svelte.ts                    (status + config snippets)
    approvals.svelte.ts              (pending queue, respond)
    toast.svelte.ts                  (globalNotice / globalError)
  components/
    SidebarNav.svelte
    TopBar.svelte
    ModePill.svelte
    CopyButton.svelte
    Toast.svelte
    ContextMenu.svelte
    LockedCard.svelte
    RecoveryPhraseBanner.svelte
    ContainerRow.svelte
    NewContainerModal.svelte
    FileRow.svelte
    UploadDropzone.svelte
    ApprovalBanner.svelte
    FileViewerModal.svelte
    ApprovalModal.svelte
    OtpModal.svelte
  pages/
    VaultPage.svelte
    FilesPage.svelte
    SettingsPage.svelte
```

**Modify:**
```
ui/package.json        (add 4 deps)
ui/src/main.ts         (add app.css import)
```

**Rename:**
```
ui/src/App.svelte  →  ui/src/App.legacy.svelte   (parity reference, deleted in Task 13)
```

---

## Task 1: Install deps + scaffold folders

**Files:**
- Modify: `ui/package.json`
- Create dirs: `ui/src/lib/`, `ui/src/stores/`, `ui/src/components/`, `ui/src/pages/`
- Rename: `ui/src/App.svelte` → `ui/src/App.legacy.svelte`

- [ ] **Step 1: Install dependencies**

```bash
cd C:/Users/pealm/Code/sovereign-vault/ui
npm install @fontsource/space-grotesk @fontsource/fira-mono lucide-svelte svelte-spa-router
```

Expected: packages added to `node_modules`, `package-lock.json` updated.

- [ ] **Step 2: Create directory skeleton**

```bash
mkdir -p C:/Users/pealm/Code/sovereign-vault/ui/src/lib
mkdir -p C:/Users/pealm/Code/sovereign-vault/ui/src/stores
mkdir -p C:/Users/pealm/Code/sovereign-vault/ui/src/components
mkdir -p C:/Users/pealm/Code/sovereign-vault/ui/src/pages
```

- [ ] **Step 3: Rename App.svelte to App.legacy.svelte**

```bash
cp C:/Users/pealm/Code/sovereign-vault/ui/src/App.svelte \
   C:/Users/pealm/Code/sovereign-vault/ui/src/App.legacy.svelte
```

- [ ] **Step 4: Create stub App.svelte so the project still compiles**

Create `ui/src/App.svelte`:

```svelte
<script lang="ts">
  // Stub — replaced in Task 7
</script>

<div class="app-shell">
  <p style="color:white;padding:2rem">Migrating…</p>
</div>
```

- [ ] **Step 5: Run check — must pass**

```bash
cd C:/Users/pealm/Code/sovereign-vault/ui && npm run check
```

Expected: `0 errors` (stub is valid Svelte 5).

- [ ] **Step 6: Commit**

```bash
git -C C:/Users/pealm/Code/sovereign-vault add -A
git -C C:/Users/pealm/Code/sovereign-vault commit -m "chore(ui): scaffold three-page layout — add deps, dirs, App.legacy"
```

---

## Task 2: Port app.css

**Files:**
- Create: `ui/src/app.css`
- Modify: `ui/src/main.ts`

- [ ] **Step 1: Copy legacy app.css verbatim**

```bash
cp "C:/Users/pealm/Code/agentic-sovereign-ecosystem/apps/sovereign-vault/src/app.css" \
   "C:/Users/pealm/Code/sovereign-vault/ui/src/app.css"
```

- [ ] **Step 2: Remove three out-of-scope CSS sections from `ui/src/app.css`**

Open `ui/src/app.css` and delete every rule block whose selector starts with or contains any of these:

1. **Mission-Control runtime-bar** — remove the block starting with `.runtime-bar` and all `[data-runtime="..."]` variants.
2. **Import Wizard** — remove `.wizard-grid`, `.import-draft-head`, `.file-settings-grid`, `.ops-strip` and their children.
3. **Dashboard** — remove `.dashboard-columns`, `.metric-grid`, `.metric-card`, `.code-card-header` and their children.

To identify them: grep for each selector, find the matching `{` and closing `}`, delete the full block.

- [ ] **Step 3: Add font + CSS import to `ui/src/main.ts`**

Edit `ui/src/main.ts` to:

```typescript
import '@fontsource/space-grotesk/400.css';
import '@fontsource/space-grotesk/500.css';
import '@fontsource/space-grotesk/700.css';
import '@fontsource/fira-mono/400.css';
import '@fontsource/fira-mono/500.css';
import './app.css';
import { mount } from 'svelte';
import App from './App.svelte';

const target = document.getElementById('app');
if (!target) throw new Error('No #app element');
mount(App, { target });
```

- [ ] **Step 4: Run check**

```bash
cd C:/Users/pealm/Code/sovereign-vault/ui && npm run check
```

Expected: `0 errors`.

- [ ] **Step 5: Commit**

```bash
git -C C:/Users/pealm/Code/sovereign-vault add ui/src/app.css ui/src/main.ts
git -C C:/Users/pealm/Code/sovereign-vault commit -m "feat(ui): port design system CSS from legacy sovereign-vault"
```

---

## Task 3: lib/types.ts, lib/tauri.ts, lib/formatters.ts

**Files:**
- Create: `ui/src/lib/types.ts`
- Create: `ui/src/lib/tauri.ts`
- Create: `ui/src/lib/formatters.ts`

- [ ] **Step 1: Create `ui/src/lib/types.ts`**

```typescript
export type Custody = 'OsKeychain' | 'Passphrase' | 'Recovery';

export type Mode = 'DIRECT' | 'APPROVAL' | 'OTP' | 'ANONYMIZED' | 'ZKP' | 'NATIVE';

export interface ContainerInfo {
  name: string;
  mode: Mode;
  fileCount: number;
  description?: string | null;
}

export interface FileInfo {
  name: string;
  byteSize: number;
  modifiedAt: string;
  mode: Mode;
}

export interface VaultStatus {
  initialized: boolean;
  unlocked: boolean;
  custody: Custody | null;
  has_keychain_entry: boolean;
  has_passphrase_salt: boolean;
  has_recovery_bundle: boolean;
}

export interface VaultInitResponse {
  recovery_phrase: string;
}

export interface ApprovalPrompt {
  id: number;
  action: string;
  container: string | null;
  file_name: string | null;
  mode: string | null;
  byte_size: number | null;
  otp_code: string | null;
}

export interface McpStatus {
  running: boolean;
  pairing_secret: string | null;
  ws_url: string;
  http_url: string;
}
```

- [ ] **Step 2: Create `ui/src/lib/tauri.ts`**

```typescript
import { invoke as tauriInvoke } from '@tauri-apps/api/core';

export function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return tauriInvoke<T>(cmd, args);
}
```

- [ ] **Step 3: Create `ui/src/lib/formatters.ts`**

```typescript
import type { Mode } from './types';

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

export function modeClass(mode: Mode): string {
  const map: Record<Mode, string> = {
    DIRECT: 'mode-direct',
    APPROVAL: 'mode-approval',
    OTP: 'mode-otp',
    ANONYMIZED: 'mode-anon',
    ZKP: 'mode-zkp',
    NATIVE: 'mode-native',
  };
  return map[mode] ?? 'mode-direct';
}
```

- [ ] **Step 4: Run check**

```bash
cd C:/Users/pealm/Code/sovereign-vault/ui && npm run check
```

Expected: `0 errors`.

- [ ] **Step 5: Commit**

```bash
git -C C:/Users/pealm/Code/sovereign-vault add ui/src/lib/
git -C C:/Users/pealm/Code/sovereign-vault commit -m "feat(ui): add lib/types, lib/tauri invoke wrapper, lib/formatters"
```

---

## Task 4: Svelte 5 rune stores

**Files:**
- Create: `ui/src/stores/toast.svelte.ts`
- Create: `ui/src/stores/vault.svelte.ts`
- Create: `ui/src/stores/containers.svelte.ts`
- Create: `ui/src/stores/files.svelte.ts`
- Create: `ui/src/stores/mcp.svelte.ts`
- Create: `ui/src/stores/approvals.svelte.ts`

All stores use Svelte 5 runes. The `.svelte.ts` extension enables rune syntax outside components.

- [ ] **Step 1: Create `ui/src/stores/toast.svelte.ts`**

```typescript
let notice = $state('');
let errorMsg = $state('');
let noticeTimer: ReturnType<typeof setTimeout> | null = null;
let errorTimer: ReturnType<typeof setTimeout> | null = null;

export const toastStore = {
  get notice() { return notice; },
  get error() { return errorMsg; },

  setNotice(msg: string, duration = 4000) {
    notice = msg;
    if (noticeTimer) clearTimeout(noticeTimer);
    noticeTimer = setTimeout(() => { notice = ''; }, duration);
  },

  setError(e: unknown, duration = 6000) {
    errorMsg = e instanceof Error ? e.message : String(e);
    if (errorTimer) clearTimeout(errorTimer);
    errorTimer = setTimeout(() => { errorMsg = ''; }, duration);
  },
};
```

- [ ] **Step 2: Create `ui/src/stores/vault.svelte.ts`**

```typescript
import { invoke } from '../lib/tauri';
import type { VaultStatus, Custody, VaultInitResponse } from '../lib/types';

let status = $state<VaultStatus | null>(null);
let recoveryPhrase = $state('');
let loading = $state(false);

export const vaultStore = {
  get status() { return status; },
  get recoveryPhrase() { return recoveryPhrase; },
  get loading() { return loading; },

  clearRecoveryPhrase() { recoveryPhrase = ''; },

  async refresh() {
    status = await invoke<VaultStatus>('vault_status');
  },

  async init(custody: Custody, passphrase: string | null) {
    loading = true;
    try {
      const res = await invoke<VaultInitResponse>('vault_init', { custody, passphrase });
      recoveryPhrase = res.recovery_phrase;
      await this.refresh();
    } finally {
      loading = false;
    }
  },

  async unlock(custody: Custody, passphrase: string | null) {
    loading = true;
    try {
      await invoke<void>('vault_unlock', { custody, passphrase });
      await this.refresh();
    } finally {
      loading = false;
    }
  },

  async unlockRecovery(phrase: string) {
    loading = true;
    try {
      await invoke<void>('vault_unlock_recovery', { phrase });
      await this.refresh();
    } finally {
      loading = false;
    }
  },

  async lock() {
    await invoke<void>('vault_lock');
    await this.refresh();
  },
};
```

- [ ] **Step 3: Create `ui/src/stores/containers.svelte.ts`**

```typescript
import { invoke } from '../lib/tauri';
import type { ContainerInfo, Mode } from '../lib/types';

let containers = $state<ContainerInfo[]>([]);
let loading = $state(false);

export const containerStore = {
  get list() { return containers; },
  get loading() { return loading; },

  async refresh() {
    loading = true;
    try {
      containers = await invoke<ContainerInfo[]>('vault_list_containers');
    } finally {
      loading = false;
    }
  },

  async create(name: string, mode: Mode, description: string) {
    await invoke<void>('vault_create_container', { name, mode, description });
    await this.refresh();
  },

  async remove(name: string) {
    await invoke<void>('vault_delete_container', { name });
    await this.refresh();
  },
};
```

- [ ] **Step 4: Create `ui/src/stores/files.svelte.ts`**

```typescript
import { invoke } from '../lib/tauri';
import type { FileInfo } from '../lib/types';

let files = $state<FileInfo[]>([]);
let activeContainer = $state<string | null>(null);
let loading = $state(false);

export const fileStore = {
  get files() { return files; },
  get activeContainer() { return activeContainer; },
  get loading() { return loading; },

  async refresh(container: string) {
    activeContainer = container;
    loading = true;
    try {
      files = await invoke<FileInfo[]>('vault_list_files', { container });
    } finally {
      loading = false;
    }
  },

  async write(container: string, name: string, content: Uint8Array) {
    await invoke<void>('vault_write_file', {
      container,
      name,
      content: Array.from(content),
    });
    if (activeContainer === container) await this.refresh(container);
  },

  async read(container: string, name: string): Promise<Uint8Array> {
    const arr = await invoke<number[]>('vault_read_file', { container, name });
    return new Uint8Array(arr);
  },

  async remove(container: string, name: string) {
    await invoke<void>('vault_delete_file', { container, name });
    if (activeContainer === container) await this.refresh(container);
  },
};
```

- [ ] **Step 5: Create `ui/src/stores/mcp.svelte.ts`**

```typescript
import { invoke } from '../lib/tauri';
import type { McpStatus } from '../lib/types';

let status = $state<McpStatus | null>(null);
let cliBinary = $state('<path-to-sovereign-vault>');

function makeStdioConfig(bin: string) {
  return JSON.stringify(
    { mcpServers: { sovereign_vault: { command: bin, args: ['mcp-stdio'] } } },
    null,
    2
  );
}

export const mcpStore = {
  get status() { return status; },
  get claudeConfig() { return makeStdioConfig(cliBinary); },
  get cursorConfig() { return makeStdioConfig(cliBinary); },
  get continueConfig() {
    return JSON.stringify(
      {
        mcpServerConfigs: [
          { transport: { type: 'stdio', command: cliBinary, args: ['mcp-stdio'] } },
        ],
      },
      null,
      2
    );
  },

  async refresh() {
    status = await invoke<McpStatus>('mcp_status');
    try {
      cliBinary = await invoke<string>('cli_binary_path');
    } catch {
      // command may not exist in all builds; keep default placeholder
    }
  },
};
```

- [ ] **Step 6: Create `ui/src/stores/approvals.svelte.ts`**

```typescript
import { invoke } from '../lib/tauri';
import type { ApprovalPrompt } from '../lib/types';

let queue = $state<ApprovalPrompt[]>([]);

export const approvalStore = {
  get queue() { return queue; },

  push(prompt: ApprovalPrompt) {
    const idx = queue.findIndex((p) => p.id === prompt.id);
    if (idx >= 0) {
      queue[idx] = prompt;
    } else {
      queue = [...queue, prompt];
    }
  },

  remove(id: number) {
    queue = queue.filter((p) => p.id !== id);
  },

  async respond(id: number, approved: boolean, otpCode?: string) {
    await invoke<void>('approval_respond', {
      id,
      approved,
      otp_code: otpCode ?? null,
    });
    this.remove(id);
  },
};
```

- [ ] **Step 7: Run check**

```bash
cd C:/Users/pealm/Code/sovereign-vault/ui && npm run check
```

Expected: `0 errors`.

- [ ] **Step 8: Commit**

```bash
git -C C:/Users/pealm/Code/sovereign-vault add ui/src/stores/
git -C C:/Users/pealm/Code/sovereign-vault commit -m "feat(ui): add six Svelte 5 rune stores (vault, containers, files, mcp, approvals, toast)"
```

---

## Task 5: Atomic shared components

**Files:** Create `ui/src/components/ModePill.svelte`, `CopyButton.svelte`, `Toast.svelte`, `ContextMenu.svelte`

- [ ] **Step 1: Create `ui/src/components/ModePill.svelte`**

```svelte
<script lang="ts">
  import type { Mode } from '../lib/types';
  import { modeClass } from '../lib/formatters';
  let { mode }: { mode: Mode } = $props();
</script>

<span class="mode-pill {modeClass(mode)}">{mode}</span>
```

- [ ] **Step 2: Create `ui/src/components/CopyButton.svelte`**

```svelte
<script lang="ts">
  import { Copy, Check } from 'lucide-svelte';
  let { value, label = 'Copy' }: { value: string; label?: string } = $props();
  let copied = $state(false);
  async function doCopy() {
    await navigator.clipboard.writeText(value);
    copied = true;
    setTimeout(() => { copied = false; }, 2000);
  }
</script>

<button class="ghost-button" onclick={doCopy}>
  {#if copied}<Check size={14} />{:else}<Copy size={14} />{/if}
  {label}
</button>
```

- [ ] **Step 3: Create `ui/src/components/Toast.svelte`**

```svelte
<script lang="ts">
  import { toastStore } from '../stores/toast.svelte';
</script>

{#if toastStore.notice}
  <div class="toast toast-success">{toastStore.notice}</div>
{/if}
{#if toastStore.error}
  <div class="toast toast-error">{toastStore.error}</div>
{/if}
```

- [ ] **Step 4: Create `ui/src/components/ContextMenu.svelte`**

Port directly from the legacy source at:
`C:\Users\pealm\Code\agentic-sovereign-ecosystem\apps\sovereign-vault\src\lib\ContextMenu.svelte`

Convert Svelte 4 props (`export let`) to Svelte 5 runes (`$props()`). The file uses:
- `export let x: number`, `export let y: number`, `export let items: MenuItem[]`
- `export let onClose: () => void`

Svelte 5 conversion:
```svelte
<script lang="ts">
  import { X } from 'lucide-svelte';

  interface MenuItem {
    label: string;
    onClick: () => void;
    danger?: boolean;
  }

  let {
    x,
    y,
    items,
    onClose,
  }: { x: number; y: number; items: MenuItem[]; onClose: () => void } = $props();
</script>

<div
  class="context-menu"
  style="left:{x}px;top:{y}px"
  role="menu"
>
  {#each items as item}
    <button
      class="ctx-item"
      class:danger={item.danger}
      role="menuitem"
      onclick={() => { item.onClick(); onClose(); }}
    >
      {item.label}
    </button>
  {/each}
</div>

<div class="ctx-backdrop" role="presentation" onclick={onClose}></div>

<style>
  .context-menu {
    position: fixed;
    z-index: 200;
    background: var(--surface-strong);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.25rem 0;
    min-width: 160px;
    box-shadow: var(--shadow);
  }
  .ctx-item {
    display: block;
    width: 100%;
    text-align: left;
    padding: 0.45rem 0.9rem;
    font-size: 0.85rem;
    background: none;
    border: none;
    color: var(--text);
    cursor: pointer;
  }
  .ctx-item:hover { background: var(--accent-soft); }
  .ctx-item.danger { color: var(--red); }
  .ctx-backdrop {
    position: fixed;
    inset: 0;
    z-index: 199;
  }
</style>
```

- [ ] **Step 5: Run check**

```bash
cd C:/Users/pealm/Code/sovereign-vault/ui && npm run check
```

Expected: `0 errors`.

- [ ] **Step 6: Commit**

```bash
git -C C:/Users/pealm/Code/sovereign-vault add ui/src/components/
git -C C:/Users/pealm/Code/sovereign-vault commit -m "feat(ui): add atomic components (ModePill, CopyButton, Toast, ContextMenu)"
```

---

## Task 6: SidebarNav + TopBar

**Files:**
- Create: `ui/src/components/SidebarNav.svelte`
- Create: `ui/src/components/TopBar.svelte`

- [ ] **Step 1: Create `ui/src/components/SidebarNav.svelte`**

Port from legacy `SidebarNav.svelte`. Trim to 3 nav items (drop dashboard/mcp/agents/policy/secrets). Convert Svelte 4 → Svelte 5 runes. Use `$location` from `svelte-spa-router` for active state instead of passed `activeView` prop.

```svelte
<script lang="ts">
  import { FolderLock, Files, Settings2, ShieldCheck, Lock } from 'lucide-svelte';
  import { location, push } from 'svelte-spa-router';
  import { vaultStore } from '../stores/vault.svelte';
  import { toastStore } from '../stores/toast.svelte';

  const items = [
    { path: '/vault', label: 'Vault', icon: FolderLock },
    { path: '/files', label: 'Files', icon: Files },
    { path: '/settings', label: 'Settings', icon: Settings2 },
  ] as const;

  function isActive(path: string): boolean {
    if (path === '/vault') return $location === '/' || $location === '/vault';
    return $location.startsWith(path);
  }

  async function doLock() {
    try {
      await vaultStore.lock();
      push('/vault');
    } catch (e) {
      toastStore.setError(e);
    }
  }
</script>

<aside class="sidebar">
  <div class="brand-panel">
    <div class="brand-mark">
      <ShieldCheck size={20} />
    </div>
    <div>
      <p class="eyebrow">Sovereign Vault</p>
      <h1>Local secure context</h1>
    </div>
  </div>

  <nav class="nav-list">
    {#each items as item}
      <button
        class="nav-button"
        class:active={isActive(item.path)}
        disabled={!vaultStore.status?.unlocked}
        onclick={() => push(item.path)}
      >
        <svelte:component this={item.icon} size={16} />
        {item.label}
      </button>
    {/each}
  </nav>

  <div style="margin-top:auto">
    {#if vaultStore.status?.unlocked}
      <button class="ghost-button full-width" onclick={doLock}>
        <Lock size={14} /> Lock vault
      </button>
    {/if}
    <div class="runtime-chip" style="margin-top:0.75rem">Desktop Local</div>
  </div>
</aside>
```

- [ ] **Step 2: Create `ui/src/components/TopBar.svelte`**

Port from legacy `TopBar.svelte`. Drop browser-mode branch. Derive page title from `$location`.

```svelte
<script lang="ts">
  import { Search, RefreshCcw, FolderOpen } from 'lucide-svelte';
  import { location } from 'svelte-spa-router';
  import { vaultStore } from '../stores/vault.svelte';
  import { containerStore } from '../stores/containers.svelte';
  import { fileStore } from '../stores/files.svelte';
  import { mcpStore } from '../stores/mcp.svelte';
  import { toastStore } from '../stores/toast.svelte';

  let search = $state('');

  const titleMap: Record<string, { eyebrow: string; title: string }> = {
    vault: { eyebrow: 'Agent storage', title: 'Secure data categories' },
    files: { eyebrow: 'Vault files', title: 'Encrypted file registry' },
    settings: { eyebrow: 'Preferences', title: 'Storage and runtime' },
  };

  let pageKey = $derived(
    $location.startsWith('/files') ? 'files'
    : $location.startsWith('/settings') ? 'settings'
    : 'vault'
  );
  let meta = $derived(titleMap[pageKey]);

  async function doRefresh() {
    try {
      await vaultStore.refresh();
      await containerStore.refresh();
      if (fileStore.activeContainer) await fileStore.refresh(fileStore.activeContainer);
      await mcpStore.refresh();
      toastStore.setNotice('Refreshed.');
    } catch (e) {
      toastStore.setError(e);
    }
  }
</script>

<header class="topbar">
  <div class="topbar-title">
    <p class="eyebrow">{meta.eyebrow}</p>
    <h2>{meta.title}</h2>
  </div>

  <div class="search-shell">
    <Search size={14} class="search-icon" />
    <input
      class="search-input"
      type="search"
      placeholder="Search…"
      bind:value={search}
    />
  </div>

  <div class="topbar-actions">
    <button class="ghost-button" onclick={doRefresh} title="Refresh">
      <RefreshCcw size={15} />
    </button>
  </div>
</header>
```

- [ ] **Step 3: Run check**

```bash
cd C:/Users/pealm/Code/sovereign-vault/ui && npm run check
```

Expected: `0 errors`.

- [ ] **Step 4: Commit**

```bash
git -C C:/Users/pealm/Code/sovereign-vault add ui/src/components/SidebarNav.svelte ui/src/components/TopBar.svelte
git -C C:/Users/pealm/Code/sovereign-vault commit -m "feat(ui): port SidebarNav (3-item) and TopBar from legacy design"
```

---

## Task 7: App.svelte router shell

**Files:**
- Modify: `ui/src/App.svelte` (replace stub with real shell)

- [ ] **Step 1: Replace `ui/src/App.svelte` with the router shell**

```svelte
<script lang="ts">
  import { onMount } from 'svelte';
  import Router from 'svelte-spa-router';
  import SidebarNav from './components/SidebarNav.svelte';
  import TopBar from './components/TopBar.svelte';
  import Toast from './components/Toast.svelte';
  import LockedCard from './components/LockedCard.svelte';
  import VaultPage from './pages/VaultPage.svelte';
  import FilesPage from './pages/FilesPage.svelte';
  import SettingsPage from './pages/SettingsPage.svelte';
  import { vaultStore } from './stores/vault.svelte';
  import { containerStore } from './stores/containers.svelte';
  import { mcpStore } from './stores/mcp.svelte';
  import { approvalStore } from './stores/approvals.svelte';
  import { toastStore } from './stores/toast.svelte';
  import type { ApprovalPrompt } from './lib/types';

  const routes = {
    '/': VaultPage,
    '/vault': VaultPage,
    '/files': FilesPage,
    '/files/:container': FilesPage,
    '/settings': SettingsPage,
  };

  onMount(async () => {
    try {
      await vaultStore.refresh();
      if (vaultStore.status?.unlocked) {
        await containerStore.refresh();
        await mcpStore.refresh();
      }
    } catch (e) {
      toastStore.setError(e);
    }

    // Listen for MCP approval events from Tauri
    const { listen } = await import('@tauri-apps/api/event');
    const unlisten = await listen<ApprovalPrompt>('mcp-approval', (ev) => {
      approvalStore.push(ev.payload);
    });
    return () => unlisten();
  });
</script>

<div class="app-shell">
  <SidebarNav />
  <main class="main-shell">
    <TopBar />
    {#if !vaultStore.status?.unlocked}
      <LockedCard />
    {:else}
      <Router {routes} />
    {/if}
  </main>
</div>
<Toast />
```

Note: `LockedCard` is created in Task 8. Leave the import in place — TypeScript won't error on a missing file until `svelte-check` is run, and that file will exist before the check in Task 8.

- [ ] **Step 2: Create stub pages so check passes**

Create `ui/src/pages/VaultPage.svelte`:
```svelte
<p>VaultPage — stub</p>
```

Create `ui/src/pages/FilesPage.svelte`:
```svelte
<p>FilesPage — stub</p>
```

Create `ui/src/pages/SettingsPage.svelte`:
```svelte
<p>SettingsPage — stub</p>
```

- [ ] **Step 3: Run check (LockedCard stub needed)**

Create `ui/src/components/LockedCard.svelte` stub so check passes:
```svelte
<p>LockedCard — stub</p>
```

```bash
cd C:/Users/pealm/Code/sovereign-vault/ui && npm run check
```

Expected: `0 errors`.

- [ ] **Step 4: Commit**

```bash
git -C C:/Users/pealm/Code/sovereign-vault add ui/src/App.svelte ui/src/pages/ ui/src/components/LockedCard.svelte
git -C C:/Users/pealm/Code/sovereign-vault commit -m "feat(ui): wire App.svelte router shell with locked-state guard"
```

---

## Task 8: LockedCard + RecoveryPhraseBanner

**Files:**
- Modify: `ui/src/components/LockedCard.svelte` (replace stub)
- Create: `ui/src/components/RecoveryPhraseBanner.svelte`

- [ ] **Step 1: Write `ui/src/components/LockedCard.svelte`**

Note: `RecoveryPhraseBanner` is shown in `VaultPage` (not here). After `vault_init` completes, the vault becomes unlocked immediately — `App.svelte` switches to the Router, so `LockedCard` is unmounted before it could show the banner. `VaultPage` checks `vaultStore.recoveryPhrase` after the route renders.

```svelte
<script lang="ts">
  import { ShieldCheck } from 'lucide-svelte';
  import type { Custody } from '../lib/types';
  import { vaultStore } from '../stores/vault.svelte';
  import { containerStore } from '../stores/containers.svelte';
  import { mcpStore } from '../stores/mcp.svelte';
  import { toastStore } from '../stores/toast.svelte';

  let tab = $state<'passphrase' | 'keychain' | 'recovery'>('passphrase');
  let passphrase = $state('');
  let recoveryInput = $state('');

  let isInit = $derived(!vaultStore.status?.initialized);

  async function submit() {
    try {
      const custody: Custody =
        tab === 'keychain' ? 'OsKeychain'
        : tab === 'recovery' ? 'Recovery'
        : 'Passphrase';

      const phrase = tab === 'recovery' ? recoveryInput.trim() : null;
      const pass = tab === 'passphrase' ? passphrase : null;

      if (isInit) {
        await vaultStore.init(custody, pass);
      } else if (tab === 'recovery') {
        await vaultStore.unlockRecovery(phrase!);
      } else {
        await vaultStore.unlock(custody, pass);
      }

      if (vaultStore.status?.unlocked) {
        await containerStore.refresh();
        await mcpStore.refresh();
        toastStore.setNotice(isInit ? 'Vault initialised and unlocked.' : 'Vault unlocked.');
      }
    } catch (e) {
      toastStore.setError(e);
    }
  }
</script>

<div class="locked-wrap">
  <div class="panel-card" style="max-width:520px;width:100%;margin:auto">
    <div class="panel-header">
      <div>
        <p class="eyebrow">Sovereign Vault</p>
        <h3>{isInit ? 'Initialise vault' : 'Unlock vault'}</h3>
      </div>
      <ShieldCheck size={20} />
    </div>

    <div class="tab-row" style="display:flex;gap:0.5rem;margin-bottom:1rem">
      {#each [['passphrase','Passphrase'], ['keychain','OS Keychain'], ['recovery','Recovery']] as [id, label]}
        <button
          class="filter-chip"
          class:active={tab === id}
          onclick={() => tab = id as typeof tab}
        >{label}</button>
      {/each}
    </div>

    {#if tab === 'passphrase'}
      <label class="field">
        <span>Passphrase</span>
        <input
          type="password"
          placeholder="Enter passphrase…"
          bind:value={passphrase}
        />
      </label>
    {/if}

    {#if tab === 'recovery'}
      <label class="field">
        <span>Recovery phrase (24 words)</span>
        <textarea
          rows={3}
          placeholder="word1 word2 word3…"
          bind:value={recoveryInput}
        ></textarea>
      </label>
    {/if}

    {#if tab === 'keychain'}
      <p style="color:var(--muted);font-size:0.85rem">
        OS Keychain will be used — no passphrase entry needed.
      </p>
    {/if}

    <button
      class="primary-button"
      style="width:100%;margin-top:1rem"
      disabled={vaultStore.loading}
      onclick={submit}
    >
      {isInit ? 'Initialise' : 'Unlock'}
    </button>
  </div>
</div>

<style>
  .locked-wrap {
    display: flex;
    align-items: center;
    justify-content: center;
    flex: 1;
    padding: 2rem;
  }
</style>
```

- [ ] **Step 2: Write `ui/src/components/RecoveryPhraseBanner.svelte`**

```svelte
<script lang="ts">
  import { vaultStore } from '../stores/vault.svelte';
  import CopyButton from './CopyButton.svelte';
</script>

<div class="panel-card" style="max-width:720px;width:100%;margin:auto">
  <div class="panel-header">
    <div>
      <p class="eyebrow">Important — save this now</p>
      <h3>Recovery phrase</h3>
    </div>
  </div>

  <p style="color:var(--muted);font-size:0.9rem;margin-bottom:1rem">
    This 24-word phrase is the only way to recover your vault if you lose
    your passphrase or keychain entry. Write it down and store it safely.
    It will <strong>never</strong> be shown again.
  </p>

  <pre class="font-mono" style="
    background:var(--surface);border:1px solid var(--border);
    border-radius:var(--radius);padding:1rem;
    white-space:pre-wrap;word-break:break-all;
    color:var(--accent);font-size:0.9rem;line-height:1.6
  ">{vaultStore.recoveryPhrase}</pre>

  <div style="display:flex;gap:0.75rem;margin-top:1rem;align-items:center">
    <CopyButton value={vaultStore.recoveryPhrase} label="Copy phrase" />
    <button
      class="primary-button"
      onclick={() => vaultStore.clearRecoveryPhrase()}
    >
      I've stored it safely
    </button>
  </div>
</div>
```

- [ ] **Step 3: Run check**

```bash
cd C:/Users/pealm/Code/sovereign-vault/ui && npm run check
```

Expected: `0 errors`.

- [ ] **Step 4: Commit**

```bash
git -C C:/Users/pealm/Code/sovereign-vault add ui/src/components/LockedCard.svelte ui/src/components/RecoveryPhraseBanner.svelte
git -C C:/Users/pealm/Code/sovereign-vault commit -m "feat(ui): add LockedCard (init/unlock tabs) and RecoveryPhraseBanner"
```

---

## Task 9: ContainerRow + NewContainerModal + VaultPage

**Files:**
- Create: `ui/src/components/ContainerRow.svelte`
- Create: `ui/src/components/NewContainerModal.svelte`
- Modify: `ui/src/pages/VaultPage.svelte` (replace stub)

- [ ] **Step 1: Create `ui/src/components/ContainerRow.svelte`**

```svelte
<script lang="ts">
  import { ChevronDown, ChevronRight, FolderOpen, Trash2 } from 'lucide-svelte';
  import type { ContainerInfo } from '../lib/types';
  import ModePill from './ModePill.svelte';
  import ContextMenu from './ContextMenu.svelte';
  import { containerStore } from '../stores/containers.svelte';
  import { toastStore } from '../stores/toast.svelte';
  import { push } from 'svelte-spa-router';

  let { container }: { container: ContainerInfo } = $props();

  let expanded = $state(false);
  let ctx = $state<{ x: number; y: number } | null>(null);

  async function doDelete() {
    if (!confirm(`Delete container "${container.name}" and all its files?`)) return;
    try {
      await containerStore.remove(container.name);
      toastStore.setNotice(`Container "${container.name}" deleted.`);
    } catch (e) {
      toastStore.setError(e);
    }
  }

  function openFiles() {
    push(`/files/${encodeURIComponent(container.name)}`);
  }
</script>

<article class="vault-row">
  <div
    class="vault-summary"
    role="button"
    tabindex="0"
    onclick={() => expanded = !expanded}
    onkeydown={(e) => e.key === 'Enter' && (expanded = !expanded)}
    oncontextmenu={(e) => { e.preventDefault(); ctx = { x: e.clientX, y: e.clientY }; }}
  >
    {#if expanded}<ChevronDown size={15} />{:else}<ChevronRight size={15} />{/if}
    <FolderOpen size={16} style="color:var(--accent)" />
    <div class="vault-meta">
      <strong>{container.name}</strong>
      {#if container.description}<span class="hint">{container.description}</span>{/if}
    </div>
    <span class="timestamp-chip">{container.fileCount} files</span>
    <ModePill mode={container.mode} />
  </div>

  {#if expanded}
    <div class="vault-contents">
      <button class="ghost-button" onclick={openFiles}>
        <FolderOpen size={14} /> Open in Files
      </button>
      <button class="ghost-button" style="color:var(--red)" onclick={doDelete}>
        <Trash2 size={14} /> Delete
      </button>
    </div>
  {/if}
</article>

{#if ctx}
  <ContextMenu
    x={ctx.x}
    y={ctx.y}
    items={[
      { label: 'Open in Files', onClick: openFiles },
      { label: 'Delete', danger: true, onClick: doDelete },
    ]}
    onClose={() => ctx = null}
  />
{/if}
```

- [ ] **Step 2: Create `ui/src/components/NewContainerModal.svelte`**

```svelte
<script lang="ts">
  import { X } from 'lucide-svelte';
  import type { Mode } from '../lib/types';
  import ModePill from './ModePill.svelte';
  import { containerStore } from '../stores/containers.svelte';
  import { toastStore } from '../stores/toast.svelte';

  let { onClose }: { onClose: () => void } = $props();

  const modes: Mode[] = ['DIRECT', 'APPROVAL', 'OTP', 'ANONYMIZED', 'ZKP', 'NATIVE'];

  let name = $state('');
  let mode = $state<Mode>('DIRECT');
  let description = $state('');
  let saving = $state(false);

  async function save() {
    if (!name.trim()) { toastStore.setError('Name required.'); return; }
    saving = true;
    try {
      await containerStore.create(name.trim(), mode, description.trim());
      toastStore.setNotice(`Container "${name}" created.`);
      onClose();
    } catch (e) {
      toastStore.setError(e);
    } finally {
      saving = false;
    }
  }
</script>

<div class="modal-shell" role="dialog" aria-modal="true">
  <div class="modal-card panel-card" style="max-width:480px;width:100%">
    <div class="panel-header">
      <div>
        <p class="eyebrow">New vault</p>
        <h3>Create container</h3>
      </div>
      <button class="ghost-button" onclick={onClose}><X size={16} /></button>
    </div>

    <label class="field">
      <span>Name</span>
      <input type="text" placeholder="my-vault" bind:value={name} />
    </label>

    <label class="field" style="margin-top:0.75rem">
      <span>Description (optional)</span>
      <input type="text" placeholder="What's stored here…" bind:value={description} />
    </label>

    <div style="margin-top:0.75rem">
      <span class="eyebrow" style="display:block;margin-bottom:0.5rem">Security mode</span>
      <div style="display:flex;flex-wrap:wrap;gap:0.5rem">
        {#each modes as m}
          <button
            class="filter-chip"
            class:active={mode === m}
            onclick={() => mode = m}
          ><ModePill mode={m} /></button>
        {/each}
      </div>
    </div>

    <div style="display:flex;gap:0.75rem;margin-top:1.25rem;justify-content:flex-end">
      <button class="ghost-button" onclick={onClose}>Cancel</button>
      <button class="primary-button" disabled={saving} onclick={save}>Create</button>
    </div>
  </div>
</div>
```

- [ ] **Step 3: Write `ui/src/pages/VaultPage.svelte`**

Note: `RecoveryPhraseBanner` is shown here — it becomes visible immediately after `vault_init` because the vault is unlocked and the Router renders `VaultPage`. The banner dismisses when the user clicks "I've stored it safely" (calls `vaultStore.clearRecoveryPhrase()`).

```svelte
<script lang="ts">
  import { Plus } from 'lucide-svelte';
  import { onMount } from 'svelte';
  import ContainerRow from '../components/ContainerRow.svelte';
  import NewContainerModal from '../components/NewContainerModal.svelte';
  import RecoveryPhraseBanner from '../components/RecoveryPhraseBanner.svelte';
  import { containerStore } from '../stores/containers.svelte';
  import { vaultStore } from '../stores/vault.svelte';
  import { toastStore } from '../stores/toast.svelte';

  let showNew = $state(false);

  onMount(async () => {
    if (vaultStore.status?.unlocked) {
      try { await containerStore.refresh(); }
      catch (e) { toastStore.setError(e); }
    }
  });
</script>

{#if vaultStore.recoveryPhrase}
  <RecoveryPhraseBanner />
{/if}

<section class="panel-card">
  <div class="panel-header">
    <div>
      <p class="eyebrow">Vault layout</p>
      <h3>Vaults &amp; folders</h3>
    </div>
    <button class="ghost-button" onclick={() => showNew = true}>
      <Plus size={14} /> New vault
    </button>
  </div>

  {#if containerStore.loading}
    <div class="empty-state">Loading…</div>
  {:else if containerStore.list.length === 0}
    <div class="empty-state">No containers yet. Create one to get started.</div>
  {:else}
    <div class="vault-list">
      {#each containerStore.list as container (container.name)}
        <ContainerRow {container} />
      {/each}
    </div>
  {/if}
</section>

{#if showNew}
  <NewContainerModal onClose={() => showNew = false} />
{/if}
```

- [ ] **Step 4: Run check**

```bash
cd C:/Users/pealm/Code/sovereign-vault/ui && npm run check
```

Expected: `0 errors`.

- [ ] **Step 5: Commit**

```bash
git -C C:/Users/pealm/Code/sovereign-vault add ui/src/components/ContainerRow.svelte ui/src/components/NewContainerModal.svelte ui/src/pages/VaultPage.svelte
git -C C:/Users/pealm/Code/sovereign-vault commit -m "feat(ui): implement VaultPage — ContainerRow, NewContainerModal, vault list"
```

---

## Task 10: FileRow + UploadDropzone + ApprovalBanner

**Files:**
- Create: `ui/src/components/FileRow.svelte`
- Create: `ui/src/components/UploadDropzone.svelte`
- Create: `ui/src/components/ApprovalBanner.svelte`

- [ ] **Step 1: Create `ui/src/components/FileRow.svelte`**

```svelte
<script lang="ts">
  import { Eye, Download, Trash2 } from 'lucide-svelte';
  import type { FileInfo } from '../lib/types';
  import ModePill from './ModePill.svelte';
  import { formatBytes, formatDate } from '../lib/formatters';
  import { fileStore } from '../stores/files.svelte';
  import { toastStore } from '../stores/toast.svelte';
  import { save } from '@tauri-apps/plugin-dialog';
  import { writeFile } from '@tauri-apps/plugin-fs';

  let {
    file,
    container,
    onPreview,
  }: { file: FileInfo; container: string; onPreview: (f: FileInfo) => void } = $props();

  async function doDelete() {
    if (!confirm(`Delete "${file.name}"?`)) return;
    try {
      await fileStore.remove(container, file.name);
      toastStore.setNotice(`"${file.name}" deleted.`);
    } catch (e) {
      toastStore.setError(e);
    }
  }

  async function doDownload() {
    try {
      const bytes = await fileStore.read(container, file.name);
      const dest = await save({ defaultPath: file.name });
      if (!dest) return;
      await writeFile(dest, bytes);
      toastStore.setNotice(`Saved to ${dest}`);
    } catch (e) {
      toastStore.setError(e);
    }
  }
</script>

<tr class="vault-table-row">
  <td class="item-cell">
    <span class="item-name">{file.name}</span>
    <span class="item-path" style="color:var(--muted);font-size:0.8rem">{container}</span>
  </td>
  <td><ModePill mode={file.mode} /></td>
  <td style="color:var(--muted)">{formatBytes(file.byteSize)}</td>
  <td style="color:var(--muted)">{formatDate(file.modifiedAt)}</td>
  <td>
    <div style="display:flex;gap:0.4rem">
      <button class="ghost-button" title="Preview" onclick={() => onPreview(file)}>
        <Eye size={13} />
      </button>
      <button class="ghost-button" title="Download" onclick={doDownload}>
        <Download size={13} />
      </button>
      <button class="ghost-button" style="color:var(--red)" title="Delete" onclick={doDelete}>
        <Trash2 size={13} />
      </button>
    </div>
  </td>
</tr>
```

- [ ] **Step 2: Create `ui/src/components/UploadDropzone.svelte`**

```svelte
<script lang="ts">
  import { Upload } from 'lucide-svelte';
  import { fileStore } from '../stores/files.svelte';
  import { toastStore } from '../stores/toast.svelte';

  let { container }: { container: string } = $props();

  let dragging = $state(false);
  let fileInput: HTMLInputElement;

  async function uploadFiles(list: FileList | null) {
    if (!list || list.length === 0) return;
    for (const file of Array.from(list)) {
      try {
        const bytes = new Uint8Array(await file.arrayBuffer());
        await fileStore.write(container, file.name, bytes);
        toastStore.setNotice(`Uploaded "${file.name}".`);
      } catch (e) {
        toastStore.setError(e);
      }
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    dragging = false;
    uploadFiles(e.dataTransfer?.files ?? null);
  }
</script>

<div
  class="upload-dropzone"
  class:dragging
  role="region"
  aria-label="Drop files to upload"
  ondragover={(e) => { e.preventDefault(); dragging = true; }}
  ondragleave={() => dragging = false}
  ondrop={onDrop}
>
  <Upload size={20} style="color:var(--muted)" />
  <span style="color:var(--muted);font-size:0.85rem">Drop files here or</span>
  <button class="ghost-button" onclick={() => fileInput.click()}>Browse</button>
  <input
    type="file"
    multiple
    style="display:none"
    bind:this={fileInput}
    onchange={(e) => uploadFiles((e.target as HTMLInputElement).files)}
  />
</div>

<style>
  .upload-dropzone {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 1rem;
    border: 1px dashed var(--border);
    border-radius: var(--radius);
    cursor: default;
    transition: border-color 0.15s, background 0.15s;
  }
  .upload-dropzone.dragging {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
</style>
```

- [ ] **Step 3: Create `ui/src/components/ApprovalBanner.svelte`**

```svelte
<script lang="ts">
  import { approvalStore } from '../stores/approvals.svelte';
  import { toastStore } from '../stores/toast.svelte';

  let { container }: { container: string | null } = $props();

  let pending = $derived(
    approvalStore.queue.filter(
      (p) => !container || p.container === container
    )
  );

  async function approve(id: number) {
    try { await approvalStore.respond(id, true); }
    catch (e) { toastStore.setError(e); }
  }

  async function deny(id: number) {
    try { await approvalStore.respond(id, false); }
    catch (e) { toastStore.setError(e); }
  }
</script>

{#each pending as p (p.id)}
  <div class="notice-banner">
    <strong>MCP request:</strong> {p.action}
    {#if p.file_name} — <code>{p.file_name}</code>{/if}
    <div style="display:flex;gap:0.5rem;margin-top:0.5rem">
      <button class="primary-button" onclick={() => approve(p.id)}>Approve</button>
      <button class="ghost-button" onclick={() => deny(p.id)}>Deny</button>
    </div>
  </div>
{/each}
```

- [ ] **Step 4: Run check**

```bash
cd C:/Users/pealm/Code/sovereign-vault/ui && npm run check
```

Expected: `0 errors`.

- [ ] **Step 5: Commit**

```bash
git -C C:/Users/pealm/Code/sovereign-vault add ui/src/components/FileRow.svelte ui/src/components/UploadDropzone.svelte ui/src/components/ApprovalBanner.svelte
git -C C:/Users/pealm/Code/sovereign-vault commit -m "feat(ui): add FileRow, UploadDropzone, ApprovalBanner components"
```

---

## Task 11: FileViewerModal + ApprovalModal + OtpModal + FilesPage

**Files:**
- Create: `ui/src/components/FileViewerModal.svelte`
- Create: `ui/src/components/ApprovalModal.svelte`
- Create: `ui/src/components/OtpModal.svelte`
- Modify: `ui/src/pages/FilesPage.svelte` (replace stub)

- [ ] **Step 1: Create `ui/src/components/FileViewerModal.svelte`**

```svelte
<script lang="ts">
  import { X, Download } from 'lucide-svelte';
  import type { FileInfo } from '../lib/types';
  import { fileStore } from '../stores/files.svelte';
  import { toastStore } from '../stores/toast.svelte';
  import { formatBytes } from '../lib/formatters';
  import { save } from '@tauri-apps/plugin-dialog';
  import { writeFile } from '@tauri-apps/plugin-fs';

  const MAX_PREVIEW_BYTES = 256 * 1024; // 256 KB

  let {
    file,
    container,
    onClose,
  }: { file: FileInfo; container: string; onClose: () => void } = $props();

  let content = $state<string | null>(null);
  let loading = $state(true);
  let tooLarge = $state(false);
  let rawBytes = $state<Uint8Array | null>(null);

  $effect(() => {
    loading = true;
    fileStore.read(container, file.name).then((bytes) => {
      rawBytes = bytes;
      if (bytes.length > MAX_PREVIEW_BYTES) {
        tooLarge = true;
      } else {
        content = new TextDecoder().decode(bytes);
      }
      loading = false;
    }).catch((e) => {
      toastStore.setError(e);
      loading = false;
    });
  });

  async function doDownload() {
    if (!rawBytes) return;
    try {
      const dest = await save({ defaultPath: file.name });
      if (!dest) return;
      await writeFile(dest, rawBytes);
      toastStore.setNotice(`Saved to ${dest}`);
    } catch (e) {
      toastStore.setError(e);
    }
  }
</script>

<div class="modal-shell" role="dialog" aria-modal="true">
  <div class="modal-card panel-card" style="max-width:680px;width:100%;max-height:80vh;display:flex;flex-direction:column">
    <div class="panel-header">
      <div>
        <p class="eyebrow">{container}</p>
        <h3 style="font-family:var(--font-mono);font-size:0.9rem">{file.name}</h3>
      </div>
      <div style="display:flex;gap:0.5rem">
        <button class="ghost-button" onclick={doDownload}><Download size={14} /></button>
        <button class="ghost-button" onclick={onClose}><X size={16} /></button>
      </div>
    </div>

    <p style="color:var(--muted);font-size:0.8rem;margin-bottom:0.75rem">
      {formatBytes(file.byteSize)}
    </p>

    <div style="overflow:auto;flex:1">
      {#if loading}
        <p style="color:var(--muted)">Loading…</p>
      {:else if tooLarge}
        <p style="color:var(--yellow)">
          File exceeds 256 KB preview limit. Use Download to save locally.
        </p>
      {:else if content !== null}
        <pre style="font-family:var(--font-mono);font-size:0.82rem;color:var(--text);white-space:pre-wrap;word-break:break-all">{content}</pre>
      {/if}
    </div>
  </div>
</div>
```

- [ ] **Step 2: Create `ui/src/components/ApprovalModal.svelte`**

```svelte
<script lang="ts">
  import { X } from 'lucide-svelte';
  import type { ApprovalPrompt } from '../lib/types';
  import { approvalStore } from '../stores/approvals.svelte';
  import { toastStore } from '../stores/toast.svelte';

  let { prompt, onClose }: { prompt: ApprovalPrompt; onClose: () => void } = $props();

  async function respond(approved: boolean) {
    try {
      await approvalStore.respond(prompt.id, approved);
      onClose();
    } catch (e) {
      toastStore.setError(e);
    }
  }
</script>

<div class="modal-shell" role="dialog" aria-modal="true">
  <div class="modal-card panel-card" style="max-width:440px;width:100%">
    <div class="panel-header">
      <div>
        <p class="eyebrow">MCP access request</p>
        <h3>Approval required</h3>
      </div>
      <button class="ghost-button" onclick={onClose}><X size={16} /></button>
    </div>

    <dl style="font-size:0.88rem;display:grid;grid-template-columns:auto 1fr;gap:0.4rem 1rem">
      <dt style="color:var(--muted)">Action</dt><dd>{prompt.action}</dd>
      {#if prompt.container}
        <dt style="color:var(--muted)">Container</dt><dd><code>{prompt.container}</code></dd>
      {/if}
      {#if prompt.file_name}
        <dt style="color:var(--muted)">File</dt><dd><code>{prompt.file_name}</code></dd>
      {/if}
    </dl>

    <div style="display:flex;gap:0.75rem;margin-top:1.25rem;justify-content:flex-end">
      <button class="ghost-button" onclick={() => respond(false)}>Deny</button>
      <button class="primary-button" onclick={() => respond(true)}>Approve</button>
    </div>
  </div>
</div>
```

- [ ] **Step 3: Create `ui/src/components/OtpModal.svelte`**

```svelte
<script lang="ts">
  import { X } from 'lucide-svelte';
  import type { ApprovalPrompt } from '../lib/types';
  import { approvalStore } from '../stores/approvals.svelte';
  import { toastStore } from '../stores/toast.svelte';

  let { prompt, onClose }: { prompt: ApprovalPrompt; onClose: () => void } = $props();

  let otpInput = $state('');

  async function submit() {
    if (!otpInput.trim()) { toastStore.setError('Enter the OTP code.'); return; }
    try {
      await approvalStore.respond(prompt.id, true, otpInput.trim());
      onClose();
    } catch (e) {
      toastStore.setError(e);
    }
  }
</script>

<div class="modal-shell" role="dialog" aria-modal="true">
  <div class="modal-card panel-card" style="max-width:400px;width:100%">
    <div class="panel-header">
      <div>
        <p class="eyebrow">OTP container</p>
        <h3>One-time password required</h3>
      </div>
      <button class="ghost-button" onclick={onClose}><X size={16} /></button>
    </div>

    {#if prompt.otp_code}
      <div class="notice-banner" style="font-family:var(--font-mono);font-size:1.4rem;letter-spacing:0.2em;text-align:center">
        {prompt.otp_code}
      </div>
      <p style="color:var(--muted);font-size:0.85rem;margin-top:0.75rem">
        This code was generated by the vault. Share it with the MCP caller.
      </p>
    {:else}
      <label class="field">
        <span>OTP code</span>
        <input type="text" placeholder="123456" bind:value={otpInput} />
      </label>
      <div style="display:flex;gap:0.75rem;margin-top:1rem;justify-content:flex-end">
        <button class="ghost-button" onclick={onClose}>Cancel</button>
        <button class="primary-button" onclick={submit}>Submit</button>
      </div>
    {/if}
  </div>
</div>
```

- [ ] **Step 4: Write `ui/src/pages/FilesPage.svelte`**

Note: `$effect` cannot be nested inside `onMount`. Container selection and modal auto-open are handled by top-level `$effect` blocks.

```svelte
<script lang="ts">
  import { onMount } from 'svelte';
  import { params } from 'svelte-spa-router';
  import FileRow from '../components/FileRow.svelte';
  import UploadDropzone from '../components/UploadDropzone.svelte';
  import ApprovalBanner from '../components/ApprovalBanner.svelte';
  import FileViewerModal from '../components/FileViewerModal.svelte';
  import ApprovalModal from '../components/ApprovalModal.svelte';
  import OtpModal from '../components/OtpModal.svelte';
  import ModePill from '../components/ModePill.svelte';
  import { fileStore } from '../stores/files.svelte';
  import { containerStore } from '../stores/containers.svelte';
  import { approvalStore } from '../stores/approvals.svelte';
  import { toastStore } from '../stores/toast.svelte';
  import type { FileInfo, ApprovalPrompt } from '../lib/types';

  let selectedContainer = $state<string | null>(null);
  let previewFile = $state<FileInfo | null>(null);
  let approvalModal = $state<ApprovalPrompt | null>(null);
  let otpModal = $state<ApprovalPrompt | null>(null);

  onMount(async () => {
    if (containerStore.list.length === 0) {
      try { await containerStore.refresh(); }
      catch (e) { toastStore.setError(e); }
    }
  });

  // Sync URL param → selectedContainer and load files
  $effect(() => {
    const container = $params?.container
      ? decodeURIComponent($params.container)
      : containerStore.list[0]?.name ?? null;
    if (container && container !== selectedContainer) {
      selectedContainer = container;
      fileStore.refresh(container).catch((e) => toastStore.setError(e));
    }
  });

  // Auto-open approval/OTP modals for pending requests
  $effect(() => {
    const pending = approvalStore.queue.find(
      (p) => !selectedContainer || p.container === selectedContainer
    );
    if (pending && !approvalModal && !otpModal) {
      if (pending.otp_code !== null) otpModal = pending;
      else approvalModal = pending;
    }
  });
</script>

<ApprovalBanner container={selectedContainer} />

<section class="panel-card">
  <div class="panel-header">
    <div>
      <p class="eyebrow">Imported objects</p>
      <h3>Encrypted file registry</h3>
    </div>
    {#if selectedContainer}
      <UploadDropzone container={selectedContainer} />
    {/if}
  </div>

  <!-- Container filter chips -->
  <div style="display:flex;flex-wrap:wrap;gap:0.5rem;margin-bottom:1rem">
    {#each containerStore.list as c (c.name)}
      <button
        class="filter-chip"
        class:active={selectedContainer === c.name}
        onclick={() => {
          selectedContainer = c.name;
          fileStore.refresh(c.name).catch((e) => toastStore.setError(e));
        }}
      >
        {c.name} <ModePill mode={c.mode} />
      </button>
    {/each}
  </div>

  <div class="table-shell">
    {#if fileStore.loading}
      <div class="empty-state">Loading…</div>
    {:else if fileStore.files.length === 0}
      <div class="empty-state">No files in this container yet.</div>
    {:else}
      <table class="vault-table">
        <thead>
          <tr>
            <th>Item</th>
            <th>Mode</th>
            <th>Size</th>
            <th>Modified</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each fileStore.files as file (file.name)}
            <FileRow
              {file}
              container={selectedContainer ?? ''}
              onPreview={(f) => previewFile = f}
            />
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</section>

{#if previewFile && selectedContainer}
  <FileViewerModal
    file={previewFile}
    container={selectedContainer}
    onClose={() => previewFile = null}
  />
{/if}

{#if approvalModal}
  <ApprovalModal prompt={approvalModal} onClose={() => approvalModal = null} />
{/if}

{#if otpModal}
  <OtpModal prompt={otpModal} onClose={() => otpModal = null} />
{/if}
```

- [ ] **Step 5: Run check**

```bash
cd C:/Users/pealm/Code/sovereign-vault/ui && npm run check
```

Expected: `0 errors`.

- [ ] **Step 6: Commit**

```bash
git -C C:/Users/pealm/Code/sovereign-vault add ui/src/components/FileViewerModal.svelte ui/src/components/ApprovalModal.svelte ui/src/components/OtpModal.svelte ui/src/pages/FilesPage.svelte
git -C C:/Users/pealm/Code/sovereign-vault commit -m "feat(ui): implement FilesPage — file table, modals, upload, approval flow"
```

---

## Task 12: SettingsPage

**Files:**
- Modify: `ui/src/pages/SettingsPage.svelte` (replace stub)

- [ ] **Step 1: Write `ui/src/pages/SettingsPage.svelte`**

```svelte
<script lang="ts">
  import { onMount } from 'svelte';
  import { Eye, EyeOff, FolderOpen } from 'lucide-svelte';
  import CopyButton from '../components/CopyButton.svelte';
  import ModePill from '../components/ModePill.svelte';
  import { vaultStore } from '../stores/vault.svelte';
  import { mcpStore } from '../stores/mcp.svelte';
  import { approvalStore } from '../stores/approvals.svelte';
  import { toastStore } from '../stores/toast.svelte';
  import { invoke } from '../lib/tauri';

  let appVersion = $state('…');
  let showRecovery = $state(false);
  let revealPhrase = $state(false);
  let recoveryData = $state<string | null>(null);
  let recoveryLoading = $state(false);

  onMount(async () => {
    try {
      appVersion = await invoke<string>('app_version');
      await mcpStore.refresh();
    } catch (e) {
      toastStore.setError(e);
    }
  });

  async function loadRecovery() {
    recoveryLoading = true;
    try {
      // Re-auth not implemented in v1 — show existing phrase from vault store
      // (only available right after init; otherwise prompt user to re-init)
      if (vaultStore.recoveryPhrase) {
        recoveryData = vaultStore.recoveryPhrase;
        revealPhrase = true;
      } else {
        toastStore.setError('Recovery phrase only shown immediately after vault initialisation. Re-initialise to generate a new one.');
      }
    } finally {
      recoveryLoading = false;
    }
  }

  async function openAuditFolder() {
    try {
      await invoke<void>('open_audit_folder');
    } catch (e) {
      toastStore.setError(e);
    }
  }

  const mcpTools = [
    'vault.list',
    'vault.read',
    'vault.write',
    'vault.delete',
    'vault.create_container',
  ];
</script>

<div class="settings-grid">
  <!-- Left column -->
  <div style="display:flex;flex-direction:column;gap:1rem">

    <!-- Identity & Recovery -->
    <article class="panel-card">
      <div class="panel-header">
        <div>
          <p class="eyebrow">Identity &amp; recovery</p>
          <h3>Custody settings</h3>
        </div>
      </div>

      <div class="settings-stack">
        <div class="detail-row">
          <span>Custody mode</span>
          <strong>
            {#if vaultStore.status?.custody}
              {vaultStore.status.custody}
            {:else}
              —
            {/if}
          </strong>
        </div>
        <div class="detail-row">
          <span>OS Keychain entry</span>
          <strong>{vaultStore.status?.has_keychain_entry ? 'Present' : 'None'}</strong>
        </div>
        <div class="detail-row">
          <span>Recovery bundle</span>
          <strong>{vaultStore.status?.has_recovery_bundle ? 'Present' : 'None'}</strong>
        </div>
      </div>

      <div style="display:flex;gap:0.75rem;margin-top:1rem;flex-wrap:wrap">
        <button class="ghost-button" disabled={recoveryLoading} onclick={loadRecovery}>
          {#if revealPhrase}<EyeOff size={14} />{:else}<Eye size={14} />{/if}
          Show recovery phrase
        </button>
      </div>

      {#if revealPhrase && recoveryData}
        <pre style="
          margin-top:0.75rem;font-family:var(--font-mono);font-size:0.85rem;
          background:var(--surface);border:1px solid var(--border);
          border-radius:var(--radius);padding:0.75rem;
          color:var(--accent);white-space:pre-wrap;word-break:break-all
        ">{recoveryData}</pre>
        <CopyButton value={recoveryData} label="Copy phrase" />
      {/if}
    </article>

    <!-- About -->
    <article class="panel-card">
      <div class="panel-header">
        <div>
          <p class="eyebrow">Application</p>
          <h3>About</h3>
        </div>
      </div>
      <div class="settings-stack">
        <div class="detail-row">
          <span>Version</span>
          <strong style="font-family:var(--font-mono)">{appVersion}</strong>
        </div>
        <div class="detail-row">
          <span>License</span>
          <strong>MIT</strong>
        </div>
      </div>
    </article>
  </div>

  <!-- Right column -->
  <div style="display:flex;flex-direction:column;gap:1rem">

    <!-- MCP Server -->
    <article class="panel-card">
      <div class="panel-header">
        <div>
          <p class="eyebrow">MCP integration</p>
          <h3>MCP server</h3>
        </div>
        <button class="ghost-button" onclick={() => mcpStore.refresh().catch((e) => toastStore.setError(e))}>
          Refresh
        </button>
      </div>

      <div class="settings-stack">
        <div class="detail-row">
          <span>Status</span>
          <span class="runtime-chip">
            {mcpStore.status?.running ? 'Running' : 'Stopped'}
          </span>
        </div>
        {#if mcpStore.status?.running}
          <div class="detail-row">
            <span>Endpoint</span>
            <code style="font-family:var(--font-mono);font-size:0.8rem">{mcpStore.status.ws_url}</code>
          </div>
        {/if}
      </div>

      <div style="margin-top:0.75rem">
        <p class="eyebrow" style="margin-bottom:0.5rem">Available tools</p>
        <div style="display:flex;flex-wrap:wrap;gap:0.35rem">
          {#each mcpTools as tool}
            <span class="filter-chip" style="font-family:var(--font-mono);font-size:0.8rem">{tool}</span>
          {/each}
        </div>
      </div>

      <div style="display:flex;flex-direction:column;gap:0.5rem;margin-top:1rem">
        <CopyButton value={mcpStore.claudeConfig} label="Copy Claude Desktop config" />
        <CopyButton value={mcpStore.cursorConfig} label="Copy Cursor config" />
        <CopyButton value={mcpStore.continueConfig} label="Copy Continue.dev config" />
      </div>
    </article>

    <!-- Approvals -->
    <article class="panel-card">
      <div class="panel-header">
        <div>
          <p class="eyebrow">MCP approvals</p>
          <h3>Pending requests</h3>
        </div>
        <button class="ghost-button" onclick={openAuditFolder}>
          <FolderOpen size={14} /> Open audit folder
        </button>
      </div>

      {#if approvalStore.queue.length === 0}
        <div class="empty-state">No pending approval requests.</div>
      {:else}
        {#each approvalStore.queue as p (p.id)}
          <div class="detail-row">
            <span>{p.action}</span>
            <div style="display:flex;gap:0.5rem">
              <button class="primary-button" onclick={() => approvalStore.respond(p.id, true).catch((e) => toastStore.setError(e))}>Approve</button>
              <button class="ghost-button" onclick={() => approvalStore.respond(p.id, false).catch((e) => toastStore.setError(e))}>Deny</button>
            </div>
          </div>
        {/each}
      {/if}
    </article>

  </div>
</div>
```

- [ ] **Step 2: Run check**

```bash
cd C:/Users/pealm/Code/sovereign-vault/ui && npm run check
```

Expected: `0 errors`.

- [ ] **Step 3: Commit**

```bash
git -C C:/Users/pealm/Code/sovereign-vault add ui/src/pages/SettingsPage.svelte
git -C C:/Users/pealm/Code/sovereign-vault commit -m "feat(ui): implement SettingsPage — identity, about, MCP server, approvals"
```

---

## Task 13: Cleanup + final smoke

**Files:**
- Delete: `ui/src/App.legacy.svelte`

- [ ] **Step 1: Delete the legacy parity reference**

```bash
rm C:/Users/pealm/Code/sovereign-vault/ui/src/App.legacy.svelte
```

- [ ] **Step 2: Run check one final time**

```bash
cd C:/Users/pealm/Code/sovereign-vault/ui && npm run check
```

Expected: `0 errors`.

- [ ] **Step 3: Verify cargo builds the Tauri app**

```bash
cd C:/Users/pealm/Code/sovereign-vault && cargo tauri build 2>&1 | tail -20
```

Expected: `Finished` with no errors.

- [ ] **Step 4: Commit**

```bash
git -C C:/Users/pealm/Code/sovereign-vault add -A
git -C C:/Users/pealm/Code/sovereign-vault commit -m "feat(ui): complete three-page UI redesign — delete App.legacy, final clean"
```

- [ ] **Step 5: Manual smoke-test**

Work through the checklist from spec §9:

- [ ] Fresh launch → init with Passphrase → RecoveryPhraseBanner shows → copy → "I've stored it safely" dismisses
- [ ] Init with OS Keychain → restart → still unlocked
- [ ] Wrong passphrase → `toast-error`, no JSON blob
- [ ] Recovery phrase unlock works
- [ ] Create container in each of 6 modes → `mode-pill` colors correct
- [ ] Delete container with files → confirm modal → success toast
- [ ] Sidebar Vault → Files navigation preserves container (URL param works)
- [ ] Drag-drop upload + button upload succeed
- [ ] FileViewerModal previews text + JSON under 256 KB
- [ ] Download writes correct bytes
- [ ] MCP approval from Claude Code → ApprovalBanner on Files page → Approve and Deny work
- [ ] OTP container access triggers OtpModal
- [ ] Settings → Copy Claude Desktop config → paste is valid JSON
- [ ] Settings → Open audit folder reveals correct path
- [ ] Lock from sidebar → routes to LockedCard, nav buttons disabled
- [ ] 1024px width collapses sidebar to horizontal row

---

## Notes for the implementer

- **`.svelte.ts` stores** — Svelte 5 rune syntax (`$state`, `$derived`, `$effect`) is only valid inside `.svelte` or `.svelte.ts` / `.svelte.js` files. If `svelte-check` errors with "runes not available outside Svelte files", ensure the file extension is `.svelte.ts`.
- **`svelte-spa-router` params** — `$params` is a Svelte store exported from `svelte-spa-router`. Import it with `import { params } from 'svelte-spa-router'`. Use `$params?.container` to read the `:container` URL segment.
- **`open_audit_folder` Tauri command** — referenced in SettingsPage. If this command does not exist in `lib.rs`, either add it or remove the button. Check with `grep -r "open_audit_folder" apps/desktop/src-tauri/src/`.
- **Legacy parity** — if any feature is missing from the smoke test, `App.legacy.svelte` is the authoritative reference until Task 13 deletes it.
