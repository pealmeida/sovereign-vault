<script lang="ts">
  import { vaultStore } from '../stores/vault.svelte';
  import CopyButton from './CopyButton.svelte';
</script>

<div class="panel-card" style="max-width:720px;width:100%;margin:auto">
  <div class="panel-header">
    <div>
      <p class="eyebrow">Important — save this now</p>
      <h3>Recovery phrase</h3>
    </div>
  </div>

  <p style="color:var(--muted);font-size:0.9rem;margin-bottom:1rem">
    This 24-word phrase is the only way to recover your vault if you lose
    your passphrase or keychain entry. Write it down and store it safely.
    It will <strong>never</strong> be shown again.
  </p>

  <pre class="font-mono" style="
    background:var(--surface);border:1px solid var(--border);
    border-radius:var(--radius);padding:1rem;
    white-space:pre-wrap;word-break:break-all;
    color:var(--accent);font-size:0.9rem;line-height:1.6
  ">{vaultStore.recoveryPhrase}</pre>

  <div style="display:flex;gap:0.75rem;margin-top:1rem;align-items:center">
    <CopyButton value={vaultStore.recoveryPhrase} label="Copy phrase" />
    <button
      class="primary-button"
      onclick={() => vaultStore.clearRecoveryPhrase()}
    >
      I've stored it safely
    </button>
  </div>
</div>
