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

  onMount(() => {
    let unlisten: (() => void) | undefined;

    (async () => {
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
      unlisten = await listen<ApprovalPrompt>('mcp-approval', (ev) => {
        approvalStore.push(ev.payload);
      });
    })();

    return () => unlisten?.();
  });
</script>

<div class="app-shell">
  <SidebarNav />
  <main class="main-shell">
    <TopBar />
    {#if vaultStore.status === null}
      <div class="boot-state">
        <p class="eyebrow">Sovereign Vault</p>
        <p>Loading vault status…</p>
      </div>
    {:else if !vaultStore.status.unlocked}
      <LockedCard />
    {:else}
      <Router {routes} />
    {/if}
  </main>
</div>
<Toast />

<style>
  .boot-state {
    display: flex;
    flex: 1;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    color: var(--muted);
  }
  .boot-state p { margin: 0; }
</style>
