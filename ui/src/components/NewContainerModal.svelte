<script lang="ts">
  import { X } from '@lucide/svelte';
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
      <input type="text" placeholder="my-vault" bind:value={name} autocapitalize="none" autocorrect="off" spellcheck="false" />
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
