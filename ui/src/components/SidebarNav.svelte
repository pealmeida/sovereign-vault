<script lang="ts">
  import { FolderLock, Files, Settings2, ShieldCheck, Lock } from 'lucide-svelte';
  import { router, push } from 'svelte-spa-router';
  import { vaultStore } from '../stores/vault.svelte';
  import { toastStore } from '../stores/toast.svelte';

  const items = [
    { path: '/vault', label: 'Vault', icon: FolderLock },
    { path: '/files', label: 'Files', icon: Files },
    { path: '/settings', label: 'Settings', icon: Settings2 },
  ] as const;

  function isActive(path: string): boolean {
    if (path === '/vault') return router.location === '/' || router.location === '/vault';
    return router.location.startsWith(path);
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
