<script lang="ts">
  import { X } from '@lucide/svelte';
  import { invoke } from '../lib/tauri';
  import type { ApprovalPrompt } from '../lib/types';
  import { toastStore } from '../stores/toast.svelte';

  let { prompt, onClose }: { prompt: ApprovalPrompt; onClose: () => void } = $props();

  /// The code is shown only when the backend released it: on a protected
  /// system that is after a presence verification (§7.3), via reveal().
  let revealed = $state<string | null>(null);
  let code = $derived(prompt.otp_code ?? revealed);
  let revealing = $state(false);

  async function reveal() {
    revealing = true;
    try {
      revealed = await invoke<string>('approval_reveal_otp', { id: prompt.id });
    } catch (e) {
      toastStore.setError(e);
    } finally {
      revealing = false;
    }
  }
</script>

<div class="modal-shell" role="dialog" aria-modal="true">
  <div class="modal-card panel-card" style="max-width:420px;width:100%">
    <div class="panel-header">
      <div>
        <p class="eyebrow">OTP container{prompt.container ? ` · ${prompt.container}` : ''}</p>
        <h3>One-time code</h3>
      </div>
      <button class="ghost-button" onclick={onClose}><X size={16} /></button>
    </div>

    {#if code}
      <div class="notice-banner" style="font-family:var(--font-mono);font-size:1.6rem;letter-spacing:0.3em;text-align:center">
        {code}
      </div>
    {:else if prompt.otp_reveal_required}
      <div class="notice-banner">
        The code stays hidden until your OS confirms you are at this machine.
      </div>
      <div style="display:flex;justify-content:center;margin-top:0.5rem">
        <button class="primary-button" onclick={reveal} disabled={revealing}>
          {revealing ? 'Verifying…' : 'Reveal code — verify it’s you'}
        </button>
      </div>
    {/if}
    <p style="color:var(--muted);font-size:0.85rem;margin-top:0.75rem">
      Give this code to the agent that made the request — set it as the
      <code>otp</code> argument and resend. The code is shown only here and
      entered only on the agent side, so a request can only proceed when a human
      at this desktop relays it. Expires in 2 minutes; single use.
    </p>
    <div style="display:flex;gap:0.75rem;margin-top:1rem;justify-content:flex-end">
      <button class="primary-button" onclick={onClose}>Done</button>
    </div>
  </div>
</div>
