<script lang="ts">
  import { onMount } from 'svelte';
  import { Eye, EyeOff, FolderOpen } from 'lucide-svelte';
  import CopyButton from '../components/CopyButton.svelte';
  import { vaultStore } from '../stores/vault.svelte';
  import { mcpStore } from '../stores/mcp.svelte';
  import { agentsStore } from '../stores/agents.svelte';
  import { approvalStore } from '../stores/approvals.svelte';
  import { toastStore } from '../stores/toast.svelte';
  let appVersion = $state('…');
  let revealPhrase = $state(false);
  let recoveryData = $state<string | null>(null);

  let newAgentName = $state('');
  let newAgentToken = $state<string | null>(null);

  async function createAgent() {
    const name = newAgentName.trim();
    if (!name) {
      toastStore.setError('Enter a name for the agent.');
      return;
    }
    try {
      const created = await agentsStore.create(name);
      newAgentName = '';
      newAgentToken = created.token;
      toastStore.setNotice('Agent created. Copy its token now — it is shown only once.');
    } catch (e) {
      toastStore.setError(e);
    }
  }

  async function revokeAgent(agentId: string) {
    try {
      await agentsStore.revoke(agentId);
      toastStore.setNotice('Agent revoked.');
    } catch (e) {
      toastStore.setError(e);
    }
  }

  let currentPass = $state('');
  let newPass = $state('');
  let rotatePass = $state('');

  const isPassphrase = $derived(vaultStore.status?.custody === 'Passphrase');

  async function changePassphrase() {
    try {
      await vaultStore.changePassphrase(currentPass, newPass);
      currentPass = '';
      newPass = '';
      toastStore.setNotice('Passphrase changed. Recovery phrase is unaffected.');
    } catch (e) {
      toastStore.setError(e);
    }
  }

  async function rotateKey() {
    try {
      const phrase = await vaultStore.rotateKey(isPassphrase ? rotatePass : null);
      rotatePass = '';
      recoveryData = phrase;
      revealPhrase = true;
      toastStore.setNotice('Key rotated. A new recovery phrase was issued — save it.');
    } catch (e) {
      toastStore.setError(e);
    }
  }

  onMount(async () => {
    try {
      appVersion = await vaultStore.appVersion();
      await mcpStore.refresh();
      if (vaultStore.status?.unlocked) {
        await agentsStore.refresh();
      }
    } catch (e) {
      toastStore.setError(e);
    }
  });

  function loadRecovery() {
    if (vaultStore.recoveryPhrase) {
      recoveryData = vaultStore.recoveryPhrase;
      revealPhrase = true;
    } else {
      toastStore.setError(
        'Recovery phrase only shown immediately after vault initialisation. Re-initialise to generate a new one.'
      );
    }
  }

  async function openAuditFolder() {
    try {
      await vaultStore.openAuditFolder();
    } catch (e) {
      toastStore.setError(e);
    }
  }

  const mcpTools = [
    'vault.list',
    'vault.read',
    'vault.write',
    'vault.delete',
    'vault.create_container',
  ];
</script>

<div class="settings-grid">
  <!-- Left column -->
  <div style="display:flex;flex-direction:column;gap:1rem">

    <!-- Identity & Recovery -->
    <article class="panel-card">
      <div class="panel-header">
        <div>
          <p class="eyebrow">Identity &amp; recovery</p>
          <h3>Custody settings</h3>
        </div>
      </div>

      <div class="settings-stack">
        <div class="detail-row">
          <span>Custody mode</span>
          <strong>
            {#if vaultStore.status?.custody}
              {vaultStore.status.custody}
            {:else}
              —
            {/if}
          </strong>
        </div>
        <div class="detail-row">
          <span>OS Keychain entry</span>
          <strong>{vaultStore.status?.has_keychain_entry ? 'Present' : 'None'}</strong>
        </div>
        <div class="detail-row">
          <span>Recovery bundle</span>
          <strong>{vaultStore.status?.has_recovery_bundle ? 'Present' : 'None'}</strong>
        </div>
        <div class="detail-row">
          <span>Key hierarchy</span>
          <strong>{vaultStore.status?.has_keyring ? 'Keyring (rotatable)' : 'Legacy (migrates on unlock)'}</strong>
        </div>
      </div>

      <div style="display:flex;gap:0.75rem;margin-top:1rem;flex-wrap:wrap">
        <button class="ghost-button" onclick={loadRecovery}>
          {#if revealPhrase}<EyeOff size={14} />{:else}<Eye size={14} />{/if}
          Show recovery phrase
        </button>
      </div>

      {#if revealPhrase && recoveryData}
        <pre style="
          margin-top:0.75rem;font-family:var(--font-mono);font-size:0.85rem;
          background:var(--surface);border:1px solid var(--border);
          border-radius:var(--radius);padding:0.75rem;
          color:var(--accent);white-space:pre-wrap;word-break:break-all
        ">{recoveryData}</pre>
        <CopyButton value={recoveryData} label="Copy phrase" />
      {/if}
    </article>

    <!-- Key management -->
    <article class="panel-card">
      <div class="panel-header">
        <div>
          <p class="eyebrow">Key management</p>
          <h3>Passphrase &amp; rotation</h3>
        </div>
      </div>

      {#if !vaultStore.status?.unlocked}
        <div class="empty-state">Unlock the vault to manage keys.</div>
      {:else}
        <div class="settings-stack">
          {#if isPassphrase}
            <p class="eyebrow">Change passphrase</p>
            <input
              class="text-input"
              type="password"
              placeholder="Current passphrase"
              bind:value={currentPass}
              autocomplete="current-password"
            />
            <input
              class="text-input"
              type="password"
              placeholder="New passphrase"
              bind:value={newPass}
              autocomplete="new-password"
            />
            <button
              class="primary-button"
              disabled={vaultStore.loading || !currentPass || !newPass}
              onclick={changePassphrase}
            >
              Change passphrase
            </button>
            <p style="font-size:0.8rem;opacity:0.7;margin:0.25rem 0 0">Re-wraps the data key under the new passphrase. Files are not re-encrypted; the recovery phrase still works.</p>
          {/if}

          <p class="eyebrow" style="margin-top:0.5rem">Rotate data-encryption key</p>
          {#if isPassphrase}
            <input
              class="text-input"
              type="password"
              placeholder="Confirm passphrase to rotate"
              bind:value={rotatePass}
              autocomplete="current-password"
            />
          {/if}
          <button
            class="ghost-button"
            disabled={vaultStore.loading || (isPassphrase && !rotatePass)}
            onclick={rotateKey}
          >
            Rotate key
          </button>
          <p style="font-size:0.8rem;opacity:0.7;margin:0.25rem 0 0">Generates a new key, re-encrypts every file, and issues a new recovery phrase. The old recovery phrase stops working.</p>
        </div>
      {/if}
    </article>

    <!-- About -->
    <article class="panel-card">
      <div class="panel-header">
        <div>
          <p class="eyebrow">Application</p>
          <h3>About</h3>
        </div>
      </div>
      <div class="settings-stack">
        <div class="detail-row">
          <span>Version</span>
          <strong style="font-family:var(--font-mono)">{appVersion}</strong>
        </div>
        <div class="detail-row">
          <span>License</span>
          <strong>MIT</strong>
        </div>
      </div>
    </article>
  </div>

  <!-- Right column -->
  <div style="display:flex;flex-direction:column;gap:1rem">

    <!-- MCP Server -->
    <article class="panel-card">
      <div class="panel-header">
        <div>
          <p class="eyebrow">MCP integration</p>
          <h3>MCP server</h3>
        </div>
        <button class="ghost-button" onclick={() => mcpStore.refresh().catch((e) => toastStore.setError(e))}>
          Refresh
        </button>
      </div>

      <div class="settings-stack">
        <div class="detail-row">
          <span>Status</span>
          <span class="runtime-chip" class:status-running={mcpStore.status?.running} class:status-stopped={!mcpStore.status?.running}>
            {mcpStore.status?.running ? 'Running' : 'Stopped'}
          </span>
        </div>
        {#if mcpStore.status?.running}
          <div class="detail-row">
            <span>Endpoint</span>
            <code style="font-family:var(--font-mono);font-size:0.8rem">{mcpStore.status.ws_url}</code>
          </div>
        {/if}
      </div>

      <div style="margin-top:0.75rem">
        <p class="eyebrow" style="margin-bottom:0.5rem">Available tools</p>
        <div style="display:flex;flex-wrap:wrap;gap:0.35rem">
          {#each mcpTools as tool}
            <span class="filter-chip" style="font-family:var(--font-mono);font-size:0.8rem">{tool}</span>
          {/each}
        </div>
      </div>

      <div style="display:flex;flex-direction:column;gap:0.5rem;margin-top:1rem">
        <CopyButton value={mcpStore.claudeConfig} label="Copy Claude Desktop config" />
        <CopyButton value={mcpStore.cursorConfig} label="Copy Cursor config" />
        <CopyButton value={mcpStore.continueConfig} label="Copy Continue.dev config" />
      </div>
    </article>

    <!-- Agents -->
    <article class="panel-card">
      <div class="panel-header">
        <div>
          <p class="eyebrow">MCP identity</p>
          <h3>Agents</h3>
        </div>
        <button class="ghost-button" onclick={() => agentsStore.refresh().catch((e) => toastStore.setError(e))}>
          Refresh
        </button>
      </div>

      {#if !vaultStore.status?.unlocked}
        <div class="empty-state">Unlock the vault to manage agents.</div>
      {:else}
        <div class="settings-stack">
          {#if agentsStore.agents.length === 0}
            <div class="empty-state">No agents registered.</div>
          {:else}
            {#each agentsStore.agents as agent (agent.agent_id)}
              <div class="detail-row">
                <div style="display:flex;flex-direction:column;min-width:0">
                  <strong>{agent.name}</strong>
                  <code style="font-family:var(--font-mono);font-size:0.75rem;opacity:0.7">{agent.agent_id}</code>
                </div>
                <div style="display:flex;align-items:center;gap:0.5rem">
                  {#if agent.revoked}
                    <span class="filter-chip">Revoked</span>
                  {:else}
                    <button class="ghost-button" onclick={() => revokeAgent(agent.agent_id)}>Revoke</button>
                  {/if}
                </div>
              </div>
            {/each}
          {/if}
        </div>

        <div style="display:flex;gap:0.5rem;margin-top:0.75rem">
          <input
            class="text-input"
            placeholder="New agent name"
            bind:value={newAgentName}
            style="flex:1"
          />
          <button class="primary-button" onclick={createAgent}>New agent</button>
        </div>

        {#if newAgentToken}
          <div style="margin-top:0.75rem">
            <p class="eyebrow" style="margin-bottom:0.5rem">One-time token (shown only once)</p>
            <pre style="
              white-space:pre-wrap;word-break:break-all;font-family:var(--font-mono);
              font-size:0.8rem;background:var(--surface-2,#1112);padding:0.5rem;border-radius:0.5rem;margin:0
            ">{newAgentToken}</pre>
            <div style="margin-top:0.5rem">
              <CopyButton value={newAgentToken} label="Copy token" />
            </div>
          </div>
        {/if}
      {/if}
    </article>

    <!-- Approvals -->
    <article class="panel-card">
      <div class="panel-header">
        <div>
          <p class="eyebrow">MCP approvals</p>
          <h3>Pending requests</h3>
        </div>
        <button class="ghost-button" onclick={openAuditFolder}>
          <FolderOpen size={14} /> Open audit folder
        </button>
      </div>

      {#if approvalStore.queue.length === 0}
        <div class="empty-state">No pending approval requests.</div>
      {:else}
        {#each approvalStore.queue as p (p.id)}
          <div class="detail-row">
            <span>{p.action}</span>
            <div style="display:flex;gap:0.5rem">
              <button class="primary-button" onclick={() => approvalStore.respond(p.id, true).catch((e) => toastStore.setError(e))}>Approve</button>
              <button class="ghost-button" onclick={() => approvalStore.respond(p.id, false).catch((e) => toastStore.setError(e))}>Deny</button>
            </div>
          </div>
        {/each}
      {/if}
    </article>

  </div>
</div>
