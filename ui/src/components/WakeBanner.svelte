<script lang="ts">
  import { wakeStore } from '../stores/wake.svelte';
  import { toastStore } from '../stores/toast.svelte';

  async function approve(id: number) {
    try { await wakeStore.respond(id, true); }
    catch (e) { toastStore.setError(e); }
  }

  async function deny(id: number) {
    try { await wakeStore.respond(id, false); }
    catch (e) { toastStore.setError(e); }
  }
</script>

{#each wakeStore.queue as w (w.id)}
  <div class="notice-banner" role="status">
    <strong>Wake request:</strong> agent <code>{w.agent_id}</code> asked for <code>{w.resource_ref}</code>
    <div style="display:flex;gap:0.5rem;margin-top:0.5rem">
      <button class="primary-button" onclick={() => approve(w.id)}>Allow</button>
      <button class="ghost-button" onclick={() => deny(w.id)}>Deny</button>
    </div>
  </div>
{/each}
