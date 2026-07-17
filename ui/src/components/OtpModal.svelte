<script lang="ts">
  import { X } from '@lucide/svelte';
  import type { ApprovalPrompt } from '../lib/types';

  let { prompt, onClose }: { prompt: ApprovalPrompt; onClose: () => void } = $props();
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

    {#if prompt.otp_code}
      <div class="notice-banner" style="font-family:var(--font-mono);font-size:1.6rem;letter-spacing:0.3em;text-align:center">
        {prompt.otp_code}
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
