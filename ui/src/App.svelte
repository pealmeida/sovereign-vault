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
  import ApprovalModal from './components/ApprovalModal.svelte';
  import OtpModal from './components/OtpModal.svelte';
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

      // Listen for MCP approval events from Tauri (name must match the
      // backend APPROVAL_EVENT constant in apps/desktop/src-tauri/src/lib.rs).
      const { listen } = await import('@tauri-apps/api/event');
      unlisten = await listen<ApprovalPrompt>('vault://approval-request', (ev) => {
        approvalStore.push(ev.payload);
      });
    })();

    return () => unlisten?.();
  });

  // Deny a specific request if it is still pending (e.g. modal dismissed
  // without an explicit decision). Keyed by id so resolving one request
  // never accidentally denies the next one in the queue.
  async function denyById(id: number) {
    if (approvalStore.queue.find((q) => q.id === id)) {
      try { await approvalStore.respond(id, false); } catch { /* ignore */ }
    }
  }
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

<!-- Global approval surface: any incoming MCP approval/OTP request is shown
     regardless of the active page, so an agent call never hangs invisibly. -->
{#each approvalStore.queue.slice(0, 1) as prompt (prompt.id)}
  {#if prompt.otp_code !== null}
    <OtpModal {prompt} onClose={() => denyById(prompt.id)} />
  {:else}
    <ApprovalModal {prompt} onClose={() => denyById(prompt.id)} />
  {/if}
{/each}

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
