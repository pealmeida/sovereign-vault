<script lang="ts">
  import { Plus } from '@lucide/svelte';
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
