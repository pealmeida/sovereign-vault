<script lang="ts">
  import { Search, RefreshCcw } from '@lucide/svelte';
  import { router } from 'svelte-spa-router';
  import { vaultStore } from '../stores/vault.svelte';
  import { containerStore } from '../stores/containers.svelte';
  import { fileStore } from '../stores/files.svelte';
  import { mcpStore } from '../stores/mcp.svelte';
  import { toastStore } from '../stores/toast.svelte';

  let search = $state('');

  const titleMap = {
    vault: { eyebrow: 'Agent storage', title: 'Secure data categories' },
    files: { eyebrow: 'Vault files', title: 'Encrypted file registry' },
    settings: { eyebrow: 'Preferences', title: 'Storage and runtime' },
  } satisfies Record<string, { eyebrow: string; title: string }>;

  type PageKey = keyof typeof titleMap;

  let pageKey = $derived<PageKey>(
    router.location.startsWith('/files') ? 'files'
    : router.location.startsWith('/settings') ? 'settings'
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
    <Search size={14} />
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
