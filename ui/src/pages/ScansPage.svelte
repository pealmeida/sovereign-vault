  <script lang="ts">
    import { onMount } from 'svelte';
    import { Radar, Play, FolderOpen, RefreshCw, Eye, ShieldCheck, AlertTriangle, FileKey } from '@lucide/svelte';
    import { scansStore } from '../stores/scans.svelte';
    import { vaultStore } from '../stores/vault.svelte';
    import { toastStore } from '../stores/toast.svelte';
    import type { ScanFinding, ScanVerdict } from '../lib/types';

    interface ManagedFileEntry {
      path: string;
      adapter: string;
      project: string;
    }

    // Populated by the managed-file ingestion flow (ADR-0020); the vault
    // launch adapter is wired separately. Empty until then.
    let managedFiles: ManagedFileEntry[] = [];


  onMount(async () => {
    if (vaultStore.status?.unlocked) {
      try { await scansStore.refreshHistory(); }
      catch (e) { toastStore.setError(e); }
    }
  });

  const BUILD_ARTIFACT_DIRS = ['/out/', '/dist/', '/target/', '/build/', 'node_modules'];

  function isBuildArtifact(path: string): boolean {
    return BUILD_ARTIFACT_DIRS.some((d) => path.includes(d));
  }

  function isCreditCard(finding: ScanFinding): boolean {
    return finding.kind === 'pii:credit_card';
  }

  function formatBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
  }

  function groupByKind(findings: ScanFinding[]): [string, ScanFinding[]][] {
    const groups = new Map<string, ScanFinding[]>();
    for (const f of findings) {
      const list = groups.get(f.kind) ?? [];
      list.push(f);
      groups.set(f.kind, list);
    }
    return Array.from(groups.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  }

  function badgeClassFor(confidence: string): string {
    switch (confidence) {
      case 'high': return 'status-running';
      case 'medium': return 'mode-otp';
      case 'low': return '';
      default: return '';
    }
  }

  function verdictClass(verdict: string | null): string {
    switch (verdict) {
      case 'accept': return 'status-running';
      case 'false_positive': return 'mode-otp';
      case 'ignore_rule': return 'status-stopped';
      default: return '';
    }
  }

  async function pickScanFolder() {
    try {
      const { open } = await import('@tauri-apps/plugin-dialog');
      const selected = await open({ directory: true });
      if (selected) scansStore.setScanPath(selected as string);
    } catch (e) {
      toastStore.setError(e);
    }
  }
</script>

<section class="panel-card">
  <div class="panel-header">
    <div>
      <p class="eyebrow">Project secrets</p>
      <h3>Secret scan</h3>
    </div>
    <button
      class="ghost-button"
      disabled={!vaultStore.status?.unlocked || scansStore.loading}
      onclick={() => scansStore.refreshHistory().catch((e) => toastStore.setError(e))}
    >
      <RefreshCw size={14} /> Refresh history
    </button>
  </div>

  {#if !vaultStore.status?.unlocked}
    <div class="empty-state">
      <p>Unlock the vault to run scans and view history.</p>
    </div>
  {:else}
    <!-- New scan form -->
    <div class="settings-stack" style="margin-bottom:1rem">
      <div class="field">
        <span>Project path</span>
        <div style="display:flex;gap:0.5rem">
          <input
            class="text-input"
            placeholder="C:\\path\\to\\project"
            value={scansStore.scanPath}
            oninput={(e) => scansStore.setScanPath(e.currentTarget.value)}
            style="flex:1"
          />
          <button class="ghost-button" onclick={pickScanFolder}>
            <FolderOpen size={14} /> Browse
          </button>
        </div>
      </div>
      <div class="field">
        <span>Jurisdiction packs (comma-separated, optional)</span>
        <input
          class="text-input"
          placeholder="br-lgpd, eu-gdpr"
          value={scansStore.packsInput}
          oninput={(e) => scansStore.setPacksInput(e.currentTarget.value)}
        />
      </div>
      <div class="field" style="min-width:160px">
        <span>Minimum confidence</span>
        <select
          class="text-input"
          value={scansStore.minConfidence}
          onchange={(e) => scansStore.setMinConfidence(e.currentTarget.value as '' | 'low' | 'medium' | 'high')}
        >
          <option value="">All</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
        </select>
      </div>
      <button
        class="primary-button"
        disabled={scansStore.loading}
        onclick={() => scansStore.runScan().catch((e) => toastStore.setError(e))}
      >
        <Play size={14} /> Run scan
      </button>
    </div>

    {#if scansStore.error}
      <div class="notice-banner error" role="alert">
        <AlertTriangle size={18} />
        <div>
          <p>{scansStore.error}</p>
        </div>
      </div>
    {/if}

    {#if scansStore.currentReport}
      {@const report = scansStore.currentReport}

      <!-- Always-visible coverage panel -->
      <article class="panel-card" style="margin-bottom:1rem">
        <div class="panel-header compact">
          <div>
            <p class="eyebrow">Coverage</p>
            <h3>What the scan examined</h3>
          </div>
          <button
            class="ghost-button"
            onclick={() => scansStore.storeReport(report.id).then(() => toastStore.setNotice('Report stored in vault.')).catch((e) => toastStore.setError(e))}
          >
            <ShieldCheck size={14} /> Store in vault
          </button>
        </div>
        <div style="display:grid;gap:1rem;grid-template-columns:repeat(auto-fit, minmax(160px, 1fr))">
          <div class="detail-row">
            <span>Files scanned</span>
            <strong>{report.coverage.files_scanned.toLocaleString()}</strong>
          </div>
          <div class="detail-row">
            <span>Files ignored</span>
            <strong>{report.coverage.files_ignored.toLocaleString()}</strong>
          </div>
          <div class="detail-row">
            <span>Files skipped</span>
            <strong>{report.coverage.files_skipped.toLocaleString()}</strong>
          </div>
          <div class="detail-row">
            <span>Bytes scanned</span>
            <strong>{formatBytes(report.coverage.bytes_scanned)}</strong>
          </div>
        </div>
        {#if report.coverage.suppressed.length > 0}
          <div style="margin-top:0.75rem">
            <p class="eyebrow">Suppressed findings</p>
            <div style="display:flex;flex-wrap:wrap;gap:0.5rem">
              {#each report.coverage.suppressed as s}
                <span class="filter-chip">{s.reason}: {s.count.toLocaleString()}</span>
              {/each}
            </div>
          </div>
        {/if}
        <p class="supporting-copy" style="margin-top:0.75rem;font-style:italic">
          A clean report is evidence of what the detectors found, never proof that a project contains no secrets.
        </p>
      </article>

      <!-- Filters -->
      <div class="filter-row" style="margin-bottom:1rem">
        <div class="field" style="min-width:180px">
          <span>Kind</span>
          <select
            class="text-input"
            value={scansStore.kindFilter ?? ''}
            onchange={(e) => scansStore.setKindFilter(e.currentTarget.value || null)}
          >
            <option value="">All kinds</option>
            {#each scansStore.allKinds as kind}
              <option value={kind}>{kind}</option>
            {/each}
          </select>
        </div>
        <div class="field" style="min-width:180px">
          <span>Confidence</span>
          <select
            class="text-input"
            value={scansStore.confidenceFilter}
            onchange={(e) => scansStore.setConfidenceFilter(e.currentTarget.value as '' | 'low' | 'medium' | 'high')}
          >
            <option value="">All confidence</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
          </select>
        </div>
      </div>

      <!-- Findings -->
      {#if scansStore.filteredFindings.length === 0}
        <div class="empty-state">
          <Radar size={24} />
          <p>No findings match the current filters.</p>
        </div>
      {:else}
        <div style="display:flex;flex-direction:column;gap:1rem">
          {#each groupByKind(scansStore.filteredFindings) as [kind, findings] (kind)}
            <article class="panel-card">
              <div class="panel-header compact">
                <div>
                  <p class="eyebrow">{kind}</p>
                  <h3>{findings.length.toLocaleString()} finding{findings.length === 1 ? '' : 's'}</h3>
                </div>
              </div>

              <div class="table-shell">
                <table class="vault-table">
                  <thead>
                    <tr>
                      <th>File</th>
                      <th>Line</th>
                      <th>Confidence</th>
                      <th>Preview</th>
                      <th>Triage</th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each findings as finding, idx (finding.path + finding.line + finding.start)}
                      {@const globalIndex = report.findings.indexOf(finding)}
                      <tr class="vault-table-row">
                        <td class="rationale-cell">
                          <code style="font-family:var(--font-mono);font-size:0.75rem">{finding.path}</code>
                          {#if isCreditCard(finding) && isBuildArtifact(finding.path)}
                            <div style="margin-top:0.35rem">
                              <span class="mode-pill" style="color:var(--yellow);border-color:rgba(243,201,105,0.35);background:rgba(243,201,105,0.08)">Build artifact — hex bytecode passes Luhn by chance.</span>
                            </div>
                          {/if}
                        </td>
                        <td><code class="timestamp-chip">{finding.line}</code></td>
                        <td><span class="filter-chip {badgeClassFor(finding.confidence)}">{finding.confidence}</span></td>
                        <td>
                          <code style="font-family:var(--font-mono);font-size:0.8rem">
                            {scansStore.revealed[`${report.id}:${globalIndex}`] ?? finding.preview}
                          </code>
                          {#if !scansStore.revealed[`${report.id}:${globalIndex}`]}
                            <button
                              class="ghost-button"
                              style="margin-left:0.5rem;padding:0.3rem 0.5rem;font-size:0.72rem"
                              onclick={() => scansStore.reveal(report.id, globalIndex).catch((e) => toastStore.setError(e))}
                            >
                              <Eye size={12} /> Reveal (audited)
                            </button>
                          {/if}
                        </td>
                        <td>
                          <div style="display:flex;gap:0.35rem;flex-wrap:wrap">
                            {#if finding.verdict}
                              <span class="filter-chip {verdictClass(finding.verdict)}">{finding.verdict.replace(/_/g, ' ')}</span>
                            {/if}
                            <button
                              class="ghost-button"
                              style="padding:0.3rem 0.5rem;font-size:0.72rem"
                              disabled={finding.verdict === 'accept'}
                              onclick={() => scansStore.setTriage(report.id, globalIndex, 'accept').catch((e) => toastStore.setError(e))}
                            >
                              Accept
                            </button>
                            <button
                              class="ghost-button"
                              style="padding:0.3rem 0.5rem;font-size:0.72rem"
                              disabled={finding.verdict === 'false_positive'}
                              onclick={() => scansStore.setTriage(report.id, globalIndex, 'false_positive').catch((e) => toastStore.setError(e))}
                            >
                              False positive
                            </button>
                            <button
                              class="ghost-button"
                              style="padding:0.3rem 0.5rem;font-size:0.72rem"
                              disabled={finding.verdict === 'ignore_rule'}
                              onclick={() => scansStore.setTriage(report.id, globalIndex, 'ignore_rule').catch((e) => toastStore.setError(e))}
                            >
                              Ignore rule
                            </button>
                          </div>
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            </article>
          {/each}
        </div>
      {/if}
    {/if}

    <!-- History -->
    {#if scansStore.history.length > 0}
      <article class="panel-card" style="margin-top:1rem">
        <div class="panel-header compact">
          <div>
            <p class="eyebrow">Stored reports</p>
            <h3>Scan history</h3>
          </div>
        </div>
        <div class="settings-stack">
          {#each scansStore.history as h (h.id)}
            <button
              class="list-row"
              style="width:100%;text-align:left;background:transparent"
              onclick={() => scansStore.loadReport(h.id).catch((e) => toastStore.setError(e))}
            >
              <div class="vault-meta">
                <strong>{h.scanned_path}</strong>
                <code style="font-family:var(--font-mono);font-size:0.72rem;opacity:0.7">{new Date(h.created_at).toLocaleString()}</code>
              </div>
              <span class="filter-chip">{h.finding_count.toLocaleString()} findings</span>
            </button>
          {/each}
        </div>
      </article>
    {/if}

    <!-- Managed files (ADR-0020): wholly-sensitive files moved into the
         vault, with the consumer adapter that serves them at launch. -->
    <article class="panel-card" style="margin-top:1rem">
      <div class="panel-header compact">
        <div>
          <p class="eyebrow">ADR-0020</p>
          <h3>Managed files</h3>
        </div>
      </div>
      {#if managedFiles.length === 0}
        <div class="empty-state">
          <FileKey size={24} />
          <p>No files ingested yet. Wholly-sensitive files (.env, .pem, service-account.json) can move into the vault while an adapter supplies them at launch.</p>
        </div>
      {:else}
        <div class="table-shell">
          <table class="vault-table">
            <thead>
              <tr>
                <th>File</th>
                <th>Adapter</th>
                <th>Project</th>
              </tr>
            </thead>
            <tbody>
              {#each managedFiles as entry (entry.path + entry.project)}
                <tr class="vault-table-row">
                  <td><code style="font-family:var(--font-mono);font-size:0.75rem">{entry.path}</code></td>
                  <td><span class="filter-chip">{entry.adapter}</span></td>
                  <td>{entry.project}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      <p class="supporting-copy" style="margin-top:0.75rem;font-style:italic">
        Removal of the original only happens after the consumer adapter passes its startup check. Re-created plaintext is detected at launch, not prevented.
      </p>
    </article>
  {/if}
</section>
