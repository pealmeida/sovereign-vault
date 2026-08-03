<script lang="ts">
  import { ShieldCheck } from '@lucide/svelte';
  import type { Custody } from '../lib/types';
  import { vaultStore } from '../stores/vault.svelte';
  import { containerStore } from '../stores/containers.svelte';
  import { mcpStore } from '../stores/mcp.svelte';
  import { toastStore } from '../stores/toast.svelte';

  let tab = $state<'passphrase' | 'keychain' | 'recovery'>('passphrase');
  let passphrase = $state('');
  let passphraseConfirmation = $state('');
  let recoveryInput = $state('');

  // Keep this aligned with sv_core::MIN_PASSPHRASE_CHARS. The backend remains
  // authoritative so non-UI clients receive the same validation.
  const MIN_PASSPHRASE_CHARS = 16;

  let isInit = $derived(!vaultStore.status?.initialized);
  let keychainAvailable = $derived(vaultStore.status?.keychain_available ?? true);
  let passphraseVault = $derived(!isInit && !!vaultStore.status?.has_passphrase_salt);
  let availableTabs = $derived(
    ([
      ['passphrase', 'Passphrase'],
      ['keychain', 'OS Keychain'],
      ['recovery', 'Recovery'],
    ] as const)
      .filter(([id]) => {
        if (isInit) return id !== 'recovery';
        if (id === 'passphrase') return vaultStore.status?.has_passphrase_salt;
        if (id === 'keychain') return keychainAvailable;
        return vaultStore.status?.has_recovery_bundle;
      })
      .filter(([id]) => id !== 'keychain' || keychainAvailable)
  );

  $effect(() => {
    if (!availableTabs.some(([id]) => id === tab)) {
      tab = availableTabs[0]?.[0] ?? 'passphrase';
    }
  });

  let isNewPassphrase = $derived(isInit && tab === 'passphrase');
  let passphraseLength = $derived(Array.from(passphrase).length);
  let passphraseTooShort = $derived(
    isNewPassphrase && passphraseLength < MIN_PASSPHRASE_CHARS
  );
  let passphrasesMismatch = $derived(
    isNewPassphrase && passphraseConfirmation.length > 0 && passphrase !== passphraseConfirmation
  );
  let showPassphraseTooShort = $derived(passphrase.length > 0 && passphraseTooShort);
  let canSubmit = $derived.by(() => {
    if (vaultStore.loading) return false;
    if (tab === 'recovery') return recoveryInput.trim().length > 0;
    if (isNewPassphrase) {
      return !passphraseTooShort && passphrase === passphraseConfirmation;
    }
    if (tab === 'passphrase' || (tab === 'keychain' && passphraseVault)) {
      return passphrase.length > 0;
    }
    return true;
  });

  function selectTab(next: typeof tab) {
    passphrase = '';
    passphraseConfirmation = '';
    recoveryInput = '';
    tab = next;
  }

  async function submit() {
    if (!canSubmit) return;

    try {
      const wasInit = isInit;
      let repairedKeychain = false;
      const custody: Custody =
        tab === 'keychain' ? 'OsKeychain'
        : tab === 'recovery' ? 'Recovery'
        : 'Passphrase';

      const phrase = tab === 'recovery' ? recoveryInput.trim() : null;
      const pass = tab === 'passphrase' || (tab === 'keychain' && passphraseVault)
        ? passphrase
        : null;

      if (wasInit) {
        await vaultStore.init(custody, pass);
      } else if (tab === 'recovery') {
        await vaultStore.unlockRecovery(phrase!);
        repairedKeychain = vaultStore.status?.custody === 'OsKeychain';
      } else {
        await vaultStore.unlock(custody, pass);
      }

      if (vaultStore.status?.unlocked) {
        await containerStore.refresh();
        await mcpStore.refresh();
        const baseMsg = wasInit ? 'Vault initialised and unlocked.'
          : repairedKeychain ? 'Vault recovered and OS Keychain repaired.'
          : 'Vault unlocked.';
        if (vaultStore.gatewayWarning) {
          toastStore.setNotice(`${baseMsg} ${vaultStore.gatewayWarning}`);
        } else {
          toastStore.setNotice(baseMsg);
        }
      }
    } catch (e) {
      toastStore.setError(e);
    } finally {
      passphrase = '';
      passphraseConfirmation = '';
      recoveryInput = '';
    }
  }
</script>

<div class="locked-wrap">
  <div class="panel-card" style="max-width:520px;width:100%;margin:auto">
    <div class="panel-header">
      <div>
        <p class="eyebrow">Sovereign Vault</p>
        <h3>{isInit ? 'Initialise vault' : 'Unlock vault'}</h3>
      </div>
      <ShieldCheck size={20} />
    </div>

    <div class="tab-row" style="display:flex;gap:0.5rem;margin-bottom:1rem">
      {#each availableTabs as [id, label]}
        <button
          class="filter-chip"
          class:active={tab === id}
          onclick={() => selectTab(id)}
        >{label}</button>
      {/each}
    </div>

    {#if tab === 'passphrase' || (tab === 'keychain' && passphraseVault)}
      <label class="field">
        <span>{tab === 'keychain' ? 'Current passphrase' : 'Passphrase'}</span>
        <input
          type="password"
          placeholder="Enter passphrase..."
          bind:value={passphrase}
          autocomplete={isNewPassphrase ? 'new-password' : 'current-password'}
        />
      </label>
      {#if isNewPassphrase}
        <label class="field">
          <span>Confirm passphrase</span>
          <input
            type="password"
            placeholder="Enter the same passphrase again..."
            bind:value={passphraseConfirmation}
            autocomplete="new-password"
          />
        </label>
        <p
          class:credential-error={showPassphraseTooShort || passphrasesMismatch}
          class="credential-guidance"
          aria-live="polite"
        >
          {#if showPassphraseTooShort}
            Use at least {MIN_PASSPHRASE_CHARS} characters.
          {:else if passphrasesMismatch}
            Passphrases do not match.
          {:else}
            Minimum {MIN_PASSPHRASE_CHARS} characters.
          {/if}
        </p>
      {/if}
    {/if}

    {#if tab === 'recovery'}
      <label class="field">
        <span>
          Recovery phrase
          <abbr
            title="Enter the 24 words exactly as they were issued, separated by single spaces. Order matters; case does not. The phrase restores the data-encryption key if the passphrase or OS keychain entry is lost."
            tabindex="0"
            style="text-decoration:underline dotted;cursor:help"
          >24 words</abbr>
        </span>
        <textarea
          rows={3}
          placeholder="word1 word2 word3..."
          bind:value={recoveryInput}
          autocomplete="off"
          autocapitalize="none"
          spellcheck="false"
          aria-describedby="recovery-hint"
        ></textarea>
      </label>
      <p id="recovery-hint" style="color:var(--muted);font-size:0.85rem;margin-top:0.25rem">
        Words are separated by single spaces; extra whitespace is tolerated.
        Verification rejects a phrase that contains the wrong word count or
        words outside the BIP-39 English wordlist.
      </p>
      {#if !isInit && vaultStore.status?.has_keyring && !vaultStore.status?.has_passphrase_salt}
        <p style="color:var(--muted);font-size:0.85rem">
          Recovery unlock can repair a broken OS Keychain wrapper for this vault.
        </p>
      {/if}
    {/if}

    {#if tab === 'keychain'}
      <p style="color:var(--muted);font-size:0.85rem">
        {#if passphraseVault}
          Enter the current passphrase once to move this vault to {vaultStore.status?.keychain_backend ?? 'OS Keychain'}.
        {:else}
          {vaultStore.status?.keychain_backend ?? 'OS Keychain'} will be used; no passphrase entry needed.
        {/if}
      </p>
    {/if}

    {#if !keychainAvailable && vaultStore.status?.keychain_error}
      <p style="color:var(--danger);font-size:0.85rem">
        OS Keychain unavailable: {vaultStore.status.keychain_error}
      </p>
    {/if}

    <button
      class="primary-button"
      style="width:100%;margin-top:1rem"
      disabled={!canSubmit}
      onclick={submit}
    >
      {isInit ? 'Initialise' : 'Unlock'}
    </button>
  </div>
</div>

<style>
  .locked-wrap {
    display: flex;
    align-items: center;
    justify-content: center;
    flex: 1;
    padding: 2rem;
  }

  .credential-guidance {
    margin: -0.25rem 0 0;
    color: var(--muted);
    font-size: 0.8rem;
  }

  .credential-error {
    color: var(--red);
  }
</style>
