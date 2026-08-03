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

    {#if prompt.import_summary}
      <section aria-label="Imported agent authority" style="margin-top:1rem">
        <p class="eyebrow" style="margin-bottom:0.4rem">Imported authority</p>
        <p style="margin:0 0 0.6rem;font-size:0.88rem">
          Mode: <code>{prompt.import_summary.mode}</code>
          · {prompt.import_summary.agent_count} agent{prompt.import_summary.agent_count === 1 ? '' : 's'}
        </p>
        {#each prompt.import_summary.agents as agent (agent.name)}
          <div style="border-top:1px solid var(--border);padding:0.6rem 0;font-size:0.85rem">
            <strong>{agent.name}</strong>
            {#each agent.scopes as scope, index (`${agent.name}-${index}`)}
              <div style="margin-top:0.35rem;color:var(--muted)">
                <code>{scope.container_glob}</code>
                — actions: <code>{scope.actions.join(', ')}</code>
                {#if scope.mode_ceiling}
                  — mode ceiling: <code>{scope.mode_ceiling}</code>
                {/if}
              </div>
            {/each}
          </div>
        {/each}
      </section>
    {/if}

    <div style="display:flex;gap:0.75rem;margin-top:1.25rem;justify-content:flex-end">
      <button class="ghost-button" onclick={() => respond(false)}>Deny</button>
      <button class="primary-button" onclick={() => respond(true)}>Approve</button>
    </div>
  </div>
</div>
