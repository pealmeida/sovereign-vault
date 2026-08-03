<script lang="ts">
  import { vaultStore } from '../stores/vault.svelte';
  import CopyButton from './CopyButton.svelte';

  const verificationIndexes = [3, 11, 20];
  let verificationOpen = $state(false);
  let verificationInputs = $state(['', '', '']);

  let phraseWords = $derived(
    vaultStore.recoveryPhrase.trim().split(/\s+/).filter(Boolean)
  );
  let positions = $derived(
    verificationIndexes.filter((index) => index < phraseWords.length)
  );
  let verificationMatches = $derived(
    positions.length === verificationIndexes.length
      && positions.every((wordIndex, inputIndex) => {
        const input = verificationInputs[inputIndex] ?? '';
        const expected = phraseWords[wordIndex] ?? '';
        return expected.length > 0
          && input.trim().toLowerCase() === expected.toLowerCase();
      })
  );

  function beginVerification() {
    verificationInputs = ['', '', ''];
    verificationOpen = true;
  }

  function finishVerification() {
    if (!verificationMatches) return;
    verificationInputs = ['', '', ''];
    verificationOpen = false;
    vaultStore.clearRecoveryPhrase();
  }

  function cancelVerification() {
    verificationInputs = ['', '', ''];
    verificationOpen = false;
  }
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
  <ul style="color:var(--muted);font-size:0.85rem;margin:-0.5rem 0 1rem 1.25rem;line-height:1.5">
    <li>Recommended: a <abbr title="Paper stored in a fireproof safe or safe-deposit box">paper backup</abbr> you control.</li>
    <li>Cloud-synced notes apps expose this phrase to anyone with the account.</li>
    <li>The phrase restores the DEK directly, bypassing the KEK. Anyone who reads it <em>owns the vault</em>.</li>
  </ul>

  {#if !verificationOpen}
    <pre class="font-mono" style="
      background:var(--surface);border:1px solid var(--border);
      border-radius:var(--radius);padding:1rem;
      white-space:pre-wrap;word-break:break-all;
      color:var(--accent);font-size:0.9rem;line-height:1.6
    ">{vaultStore.recoveryPhrase}</pre>

    <div style="display:flex;gap:0.75rem;margin-top:1rem;align-items:center;flex-wrap:wrap">
      <CopyButton value={vaultStore.recoveryPhrase} label="Copy phrase" />
      <button class="primary-button" onclick={beginVerification}>
        Verify my copy
      </button>
    </div>
  {/if}

  {#if verificationOpen}
    <div class="verification" aria-live="polite">
      <p>Enter these words from your stored copy before this phrase is dismissed.</p>
      <div class="verification-fields">
        {#each positions as wordIndex, inputIndex}
          <label class="field">
            <span>Word {wordIndex + 1}</span>
            <input
              type="text"
              bind:value={verificationInputs[inputIndex]}
              autocomplete="off"
              autocapitalize="none"
              spellcheck="false"
            />
          </label>
        {/each}
      </div>
      {#if verificationInputs.some((word) => word.length > 0) && !verificationMatches}
        <p class="verification-error">The verification words do not match.</p>
      {/if}
      <div class="verification-actions">
        <button class="ghost-button" onclick={cancelVerification}>Show phrase again</button>
        <button
          class="primary-button"
          disabled={!verificationMatches}
          onclick={finishVerification}
        >
          Confirm and dismiss
        </button>
      </div>
    </div>
  {/if}
</div>

<style>
  .verification {
    margin-top: 1rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
  }

  .verification > p {
    margin: 0 0 0.75rem;
    color: var(--muted);
    font-size: 0.85rem;
  }

  .verification-fields {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 0.75rem;
  }

  .verification-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
    margin-top: 1rem;
  }

  .verification .verification-error {
    margin: 0.75rem 0 0;
    color: var(--red);
  }

  @media (max-width: 620px) {
    .verification-fields {
      grid-template-columns: 1fr;
    }
  }
</style>
