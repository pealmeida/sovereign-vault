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
  import LogsPage from './pages/LogsPage.svelte';
  import ScansPage from './pages/ScansPage.svelte';
  import ApprovalModal from './components/ApprovalModal.svelte';
  import OtpModal from './components/OtpModal.svelte';
  import WakeBanner from './components/WakeBanner.svelte';
  import { vaultStore } from './stores/vault.svelte';
  import { containerStore } from './stores/containers.svelte';
  import { mcpStore } from './stores/mcp.svelte';
  import { approvalStore } from './stores/approvals.svelte';
  import { wakeStore } from './stores/wake.svelte';
  import { toastStore } from './stores/toast.svelte';
  import type { ApprovalPrompt, WakePrompt } from './lib/types';

  $effect(() => {
    if (vaultStore.status?.unlocked) {
      wakeStore.refresh().catch(() => {});
    }
  });

  const routes = {
    '/': VaultPage,
    '/vault': VaultPage,
    '/files': FilesPage,
    '/files/:container': FilesPage,
    '/settings': SettingsPage,
    '/logs': LogsPage,
    '/scans': ScansPage,
  };

  onMount(() => {
    let unlisten: (() => void) | undefined;
    let unlistenCancel: (() => void) | undefined;
    let unlistenWake: (() => void) | undefined;
    let unlistenWakeCancel: (() => void) | undefined;

    (async () => {
      try {
        await vaultStore.refresh();
        if (vaultStore.status?.unlocked) {
          await containerStore.refresh();
          await mcpStore.refresh();
          await wakeStore.refresh();
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
      // Backend cancels a pending request (timed out, superseded by a newer
      // identical request, or the caller disconnected) — drop its modal so the
      // queue never piles up with stale prompts (APPROVAL_CANCEL_EVENT).
      unlistenCancel = await listen<{ id: number }>('vault://approval-cancel', (ev) => {
        approvalStore.remove(ev.payload.id);
      });
      // Wake-on-demand notifications arrive while locked or unlocked, but the
      // UI indicator is only shown after unlock (ADR-0020 §7-8).
      unlistenWake = await listen<WakePrompt>('vault://wake-request', (ev) => {
        wakeStore.push(ev.payload);
      });
      unlistenWakeCancel = await listen<{ id: number }>('vault://wake-cancel', (ev) => {
        wakeStore.remove(ev.payload.id);
      });
    })();

    return () => {
      unlisten?.();
      unlistenCancel?.();
      unlistenWake?.();
      unlistenWakeCancel?.();
    };
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
      <WakeBanner />
      <Router {routes} />
    {/if}
  </main>
</div>
<Toast />

<!-- Global approval surface: any incoming MCP approval/OTP request is shown
     regardless of the active page, so an agent call never hangs invisibly. -->
{#each approvalStore.queue.slice(0, 1) as prompt (prompt.id)}
  {#if prompt.otp_code !== null}
    <!-- OTP is display-only: the code is entered on the agent side, so closing
         the modal just dismisses it (the challenge lives server-side until the
         agent resends with the code or it expires). -->
    <OtpModal {prompt} onClose={() => approvalStore.remove(prompt.id)} />
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
