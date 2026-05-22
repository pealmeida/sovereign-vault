<script lang="ts">
  import { ShieldCheck } from 'lucide-svelte';
  import type { Custody } from '../lib/types';
  import { vaultStore } from '../stores/vault.svelte';
  import { containerStore } from '../stores/containers.svelte';
  import { mcpStore } from '../stores/mcp.svelte';
  import { toastStore } from '../stores/toast.svelte';

  let tab = $state<'passphrase' | 'keychain' | 'recovery'>('passphrase');
  let passphrase = $state('');
  let recoveryInput = $state('');

  let isInit = $derived(!vaultStore.status?.initialized);

  async function submit() {
    try {
      const custody: Custody =
        tab === 'keychain' ? 'OsKeychain'
        : tab === 'recovery' ? 'Recovery'
        : 'Passphrase';

      const phrase = tab === 'recovery' ? recoveryInput.trim() : null;
      const pass = tab === 'passphrase' ? passphrase : null;

      if (isInit) {
        await vaultStore.init(custody, pass);
      } else if (tab === 'recovery') {
        await vaultStore.unlockRecovery(phrase!);
      } else {
        await vaultStore.unlock(custody, pass);
      }

      if (vaultStore.status?.unlocked) {
        await containerStore.refresh();
        await mcpStore.refresh();
        toastStore.setNotice(isInit ? 'Vault initialised and unlocked.' : 'Vault unlocked.');
      }
    } catch (e) {
      toastStore.setError(e);
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
      {#each [['passphrase','Passphrase'], ['keychain','OS Keychain'], ['recovery','Recovery']] as [id, label]}
        <button
          class="filter-chip"
          class:active={tab === id}
          onclick={() => tab = id as typeof tab}
        >{label}</button>
      {/each}
    </div>

    {#if tab === 'passphrase'}
      <label class="field">
        <span>Passphrase</span>
        <input
          type="password"
          placeholder="Enter passphrase…"
          bind:value={passphrase}
        />
      </label>
    {/if}

    {#if tab === 'recovery'}
      <label class="field">
        <span>Recovery phrase (24 words)</span>
        <textarea
          rows={3}
          placeholder="word1 word2 word3…"
          bind:value={recoveryInput}
        ></textarea>
      </label>
    {/if}

    {#if tab === 'keychain'}
      <p style="color:var(--muted);font-size:0.85rem">
        OS Keychain will be used — no passphrase entry needed.
      </p>
    {/if}

    <button
      class="primary-button"
      style="width:100%;margin-top:1rem"
      disabled={vaultStore.loading}
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
</style>
