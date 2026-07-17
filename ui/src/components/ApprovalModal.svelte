<script lang="ts">
  import { X } from '@lucide/svelte';
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
