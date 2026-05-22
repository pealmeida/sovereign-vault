<script lang="ts">
  import { onMount } from 'svelte';
  import FileRow from '../components/FileRow.svelte';
  import UploadDropzone from '../components/UploadDropzone.svelte';
  import ApprovalBanner from '../components/ApprovalBanner.svelte';
  import FileViewerModal from '../components/FileViewerModal.svelte';
  import ApprovalModal from '../components/ApprovalModal.svelte';
  import OtpModal from '../components/OtpModal.svelte';
  import ModePill from '../components/ModePill.svelte';
  import { fileStore } from '../stores/files.svelte';
  import { containerStore } from '../stores/containers.svelte';
  import { approvalStore } from '../stores/approvals.svelte';
  import { toastStore } from '../stores/toast.svelte';
  import type { FileInfo, ApprovalPrompt } from '../lib/types';

  // svelte-spa-router v5: URL params passed as props
  let { params: routeParams }: { params?: Record<string, string> } = $props();

  let selectedContainer = $state<string | null>(null);
  let previewFile = $state<FileInfo | null>(null);
  let approvalModal = $state<ApprovalPrompt | null>(null);
  let otpModal = $state<ApprovalPrompt | null>(null);

  onMount(async () => {
    if (containerStore.list.length === 0) {
      try { await containerStore.refresh(); }
      catch (e) { toastStore.setError(e); }
    }
  });

  // Sync URL param → selectedContainer and load files
  $effect(() => {
    const container = routeParams?.container
      ? decodeURIComponent(routeParams.container)
      : containerStore.list[0]?.name ?? null;
    if (container && container !== selectedContainer) {
      selectedContainer = container;
      fileStore.refresh(container).catch((e) => toastStore.setError(e));
    }
  });

  // Auto-open approval/OTP modals for pending requests
  $effect(() => {
    const pending = approvalStore.queue.find(
      (p) => !selectedContainer || p.container === selectedContainer
    );
    if (pending && !approvalModal && !otpModal) {
      if (pending.otp_code !== null) otpModal = pending;
      else approvalModal = pending;
    }
  });
</script>

<ApprovalBanner container={selectedContainer} />

<section class="panel-card">
  <div class="panel-header">
    <div>
      <p class="eyebrow">Imported objects</p>
      <h3>Encrypted file registry</h3>
    </div>
    {#if selectedContainer}
      <UploadDropzone container={selectedContainer} />
    {/if}
  </div>

  <!-- Container filter chips -->
  <div style="display:flex;flex-wrap:wrap;gap:0.5rem;margin-bottom:1rem">
    {#each containerStore.list as c (c.name)}
      <button
        class="filter-chip"
        class:active={selectedContainer === c.name}
        onclick={() => {
          selectedContainer = c.name;
          fileStore.refresh(c.name).catch((e) => toastStore.setError(e));
        }}
      >
        {c.name} <ModePill mode={c.mode} />
      </button>
    {/each}
  </div>

  <div class="table-shell">
    {#if fileStore.loading}
      <div class="empty-state">Loading…</div>
    {:else if fileStore.files.length === 0}
      <div class="empty-state">No files in this container yet.</div>
    {:else}
      <table class="vault-table">
        <thead>
          <tr>
            <th>Item</th>
            <th>Mode</th>
            <th>Size</th>
            <th>Modified</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each fileStore.files as file (file.name)}
            <FileRow
              {file}
              container={selectedContainer ?? ''}
              onPreview={(f) => previewFile = f}
            />
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</section>

{#if previewFile && selectedContainer}
  <FileViewerModal
    file={previewFile}
    container={selectedContainer}
    onClose={() => previewFile = null}
  />
{/if}

{#if approvalModal}
  <ApprovalModal
    prompt={approvalModal}
    onClose={async () => {
      const p = approvalModal;
      approvalModal = null;
      if (p && approvalStore.queue.find(q => q.id === p.id)) {
        try { await approvalStore.respond(p.id, false); } catch { /* ignore */ }
      }
    }}
  />
{/if}

{#if otpModal}
  <OtpModal
    prompt={otpModal}
    onClose={async () => {
      const p = otpModal;
      otpModal = null;
      if (p && approvalStore.queue.find(q => q.id === p.id)) {
        try { await approvalStore.respond(p.id, false); } catch { /* ignore */ }
      }
    }}
  />
{/if}
