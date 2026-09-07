<script lang="ts">
  import { Search, RefreshCcw, Lock } from '@lucide/svelte';
  import { router } from 'svelte-spa-router';
  import { vaultStore } from '../stores/vault.svelte';
  import { containerStore } from '../stores/containers.svelte';
  import { fileStore } from '../stores/files.svelte';
  import { mcpStore } from '../stores/mcp.svelte';
  import { toastStore } from '../stores/toast.svelte';
  import { resolveRouteMeta } from '../lib/routes';

  let search = $state('');

  let meta = $derived(resolveRouteMeta(router.location));

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
    <Search size={14} />
    <input
      class="search-input"
      type="search"
      placeholder="Search…"
      bind:value={search}
    />
  </div>

  <div class="topbar-actions">
    {#if vaultStore.status?.unlocked && (vaultStore.idleLabel !== null || vaultStore.sessionLabel !== null)}
      <span class="session-timer" title="Idle / absolute session time remaining">
        <Lock size={12} />
        {#if vaultStore.idleLabel !== null}
          idle {vaultStore.idleLabel}
        {/if}
        {#if vaultStore.sessionLabel !== null}
          · cap {vaultStore.sessionLabel}
        {/if}
      </span>
    {/if}
    <button class="ghost-button" onclick={doRefresh} title="Refresh">
      <RefreshCcw size={15} />
    </button>
  </div>
</header>
