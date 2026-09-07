<script lang="ts">
  import { onMount } from 'svelte';
  import { ScrollText, AlertTriangle, CheckCircle2, ChevronLeft, ChevronRight, RefreshCw } from '@lucide/svelte';
  import { auditStore } from '../stores/audit.svelte';
  import { vaultStore } from '../stores/vault.svelte';
  import { toastStore } from '../stores/toast.svelte';

  onMount(async () => {
    if (vaultStore.status?.unlocked) {
      try { await auditStore.refresh(); }
      catch (e) { toastStore.setError(e); }
    }
  });

  function formatDate(iso: string): string {
    const d = new Date(iso);
    return d.toLocaleString();
  }

  function badgeClassFor(decision: string): string {
    switch (decision) {
      case 'allowed': return 'status-running';
      case 'denied': return 'status-stopped';
      case 'error': return 'status-stopped';
      case 'attempted': return 'mode-otp';
      default: return '';
    }
  }
</script>

<section class="panel-card">
  <div class="panel-header">
    <div>
      <p class="eyebrow">Audit trail</p>
      <h3>Hash-chained log</h3>
    </div>
    <button
      class="ghost-button"
      disabled={!vaultStore.status?.unlocked || auditStore.loading}
      onclick={() => auditStore.refresh().catch((e) => toastStore.setError(e))}
    >
      <RefreshCw size={14} /> Refresh
    </button>
  </div>

  {#if !vaultStore.status?.unlocked}
    <div class="empty-state">
      <p>The audit log is encrypted and unreadable while the vault is locked.</p>
      <p class="supporting-copy">Unlock the vault to inspect the log.</p>
    </div>
  {:else if auditStore.loading}
    <div class="empty-state">Loading audit log…</div>
  {:else if auditStore.error}
    <div class="notice-banner error" role="alert">
      <AlertTriangle size={18} />
      <div>
        <p>Could not read the audit log.</p>
        <p class="supporting-copy">{auditStore.error}</p>
      </div>
    </div>
  {:else}
    <!-- Integrity banner -->
    {#if auditStore.verifyReport}
      {@const r = auditStore.verifyReport}
      <div
        class="notice-banner"
        class:success={r.ok && auditStore.malformedSkipped === 0}
        class:error={!r.ok || auditStore.malformedSkipped > 0}
        role="status"
      >
        {#if r.ok && auditStore.malformedSkipped === 0}
          <CheckCircle2 size={18} />
        {:else}
          <AlertTriangle size={18} />
        {/if}
        <div>
          {#if r.ok && auditStore.malformedSkipped === 0}
            <p>log integrity verified</p>
          {:else if !r.ok}
            <p>log integrity FAILED</p>
          {:else}
            <p>log integrity verified, but some records are unreadable</p>
          {/if}
          <p class="supporting-copy">
            {r.entries.toLocaleString()} authenticated entries
            {#if r.legacy_entries > 0}
              · {r.legacy_entries.toLocaleString()} legacy entries
            {/if}
            {#if auditStore.malformedSkipped > 0}
              · {auditStore.malformedSkipped.toLocaleString()} records skipped (unreadable)
            {/if}
          </p>
          {#if !r.ok}
            {#if r.first_broken !== null}
              <p class="supporting-copy">First broken record: #{r.first_broken.toLocaleString()}</p>
            {/if}
            {#if r.reason}
              <p class="supporting-copy">{r.reason}</p>
            {/if}
          {/if}
        </div>
      </div>
    {/if}

    <!-- Filters -->
    <div class="filter-row" style="margin-bottom: 1rem;">
      <div class="field" style="min-width: 180px;">
        <span>Action</span>
        <select
          class="text-input"
          value={auditStore.actionFilter ?? ''}
          onchange={(e) => auditStore.setActionFilter(e.currentTarget.value || null)}
        >
          <option value="">All actions</option>
          {#each auditStore.allActions as action}
            <option value={action}>{action}</option>
          {/each}
        </select>
      </div>
      <div class="field" style="min-width: 180px;">
        <span>Decision</span>
        <select
          class="text-input"
          value={auditStore.decisionFilter ?? ''}
          onchange={(e) => auditStore.setDecisionFilter(e.currentTarget.value || null)}
        >
          <option value="">All decisions</option>
          {#each auditStore.allDecisions as decision}
            <option value={decision}>{decision}</option>
          {/each}
        </select>
      </div>
      <div class="field" style="min-width: 120px;">
        <span>Page size</span>
        <select
          class="text-input"
          value={auditStore.pageSize}
          onchange={(e) => auditStore.setPageSize(parseInt(e.currentTarget.value, 10))}
        >
          <option value={10}>10</option>
          <option value={25}>25</option>
          <option value={50}>50</option>
          <option value={100}>100</option>
        </select>
      </div>
    </div>

    <!-- Table -->
    <div class="table-shell">
      {#if auditStore.filteredEvents.length === 0}
        <div class="empty-state">
          <ScrollText size={24} />
          <p>No audit events match the current filters.</p>
        </div>
      {:else}
        <table class="vault-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Action</th>
              <th>Decision</th>
              <th>Transport</th>
              <th>Error</th>
            </tr>
          </thead>
          <tbody>
            {#each auditStore.pageEvents as event (event.timestamp + event.action + event.decision + event.transport)}
              <tr class="vault-table-row">
                <td><code class="timestamp-chip">{formatDate(event.timestamp)}</code></td>
                <td><span class="filter-chip">{event.action}</span></td>
                <td><span class="filter-chip {badgeClassFor(event.decision)}">{event.decision}</span></td>
                <td><span class="filter-chip">{event.transport}</span></td>
                <td class="rationale-cell">
                  {#if event.error}
                    <span class="mode-pill" style="color:var(--red);border-color:rgba(255,111,124,0.35);background:rgba(255,111,124,0.08)">{event.error}</span>
                  {:else}
                    —
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>

    <!-- Pagination -->
    {#if auditStore.filteredEvents.length > 0}
      <div class="filter-row" style="margin-top: 1rem;">
        <button
          class="ghost-button"
          disabled={auditStore.page === 0}
          onclick={() => auditStore.setPage(auditStore.page - 1)}
        >
          <ChevronLeft size={14} /> Previous
        </button>
        <span class="supporting-copy">
          Page {auditStore.page + 1} of {auditStore.pageCount}
          ({auditStore.filteredEvents.length.toLocaleString()} events)
        </span>
        <button
          class="ghost-button"
          disabled={auditStore.page >= auditStore.pageCount - 1}
          onclick={() => auditStore.setPage(auditStore.page + 1)}
        >
          Next <ChevronRight size={14} />
        </button>
      </div>
    {/if}
  {/if}
</section>

<style>
  .notice-banner {
    display: flex;
    align-items: flex-start;
    gap: 0.75rem;
    margin-bottom: 1rem;
  }
  .notice-banner p { margin: 0; }
  .notice-banner .supporting-copy { font-size: 0.85rem; }
</style>
