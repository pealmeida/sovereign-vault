<script lang="ts">
  import { onMount } from 'svelte';
  import { Eye, EyeOff, FolderOpen } from 'lucide-svelte';
  import CopyButton from '../components/CopyButton.svelte';
  import { vaultStore } from '../stores/vault.svelte';
  import { mcpStore } from '../stores/mcp.svelte';
  import { approvalStore } from '../stores/approvals.svelte';
  import { toastStore } from '../stores/toast.svelte';
  import { invoke } from '../lib/tauri';

  let appVersion = $state('…');
  let revealPhrase = $state(false);
  let recoveryData = $state<string | null>(null);

  onMount(async () => {
    try {
      appVersion = await invoke<string>('app_version');
      await mcpStore.refresh();
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
      await invoke<void>('open_audit_folder');
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
          <span class="runtime-chip">
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
