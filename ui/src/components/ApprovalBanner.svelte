<script lang="ts">
  import { approvalStore } from '../stores/approvals.svelte';
  import { toastStore } from '../stores/toast.svelte';

  let { container }: { container: string | null } = $props();

  let pending = $derived(
    approvalStore.queue.filter(
      (p) => !container || p.container === container
    )
  );

  async function approve(id: number) {
    try { await approvalStore.respond(id, true); }
    catch (e) { toastStore.setError(e); }
  }

  async function deny(id: number) {
    try { await approvalStore.respond(id, false); }
    catch (e) { toastStore.setError(e); }
  }
</script>

{#each pending as p (p.id)}
  <div class="notice-banner">
    <strong>MCP request:</strong> {p.action}
    {#if p.file_name} — <code>{p.file_name}</code>{/if}
    <div style="display:flex;gap:0.5rem;margin-top:0.5rem">
      <button class="primary-button" onclick={() => approve(p.id)}>Approve</button>
      <button class="ghost-button" onclick={() => deny(p.id)}>Deny</button>
    </div>
  </div>
{/each}
