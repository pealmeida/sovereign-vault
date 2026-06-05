<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import FileRow from '../components/FileRow.svelte';
  import UploadDropzone from '../components/UploadDropzone.svelte';
  import ApprovalBanner from '../components/ApprovalBanner.svelte';
  import FileViewerModal from '../components/FileViewerModal.svelte';
  import ModePill from '../components/ModePill.svelte';
  import { fileStore } from '../stores/files.svelte';
  import { containerStore } from '../stores/containers.svelte';
  import { toastStore } from '../stores/toast.svelte';
  import type { FileInfo } from '../lib/types';

  // svelte-spa-router v5: URL params passed as props
  let { params: routeParams }: { params?: Record<string, string> } = $props();

  let selectedContainer = $state<string | null>(null);
  let previewFile = $state<FileInfo | null>(null);

  onMount(async () => {
    if (containerStore.list.length === 0) {
      try { await containerStore.refresh(); }
      catch (e) { toastStore.setError(e); }
    }
  });

  // Sync URL param → selectedContainer and load files.
  //
  // Depends ONLY on the route param and the container list. The current
  // selection is read/written inside `untrack` so a manual tab click (which
  // sets `selectedContainer` directly) does not re-trigger this effect and get
  // reverted to the first container. Precedence: explicit route target, then
  // the existing selection (preserved across list refreshes), then the first
  // container on initial load.
  $effect(() => {
    const routeContainer = routeParams?.container
      ? decodeURIComponent(routeParams.container)
      : null;
    const list = containerStore.list;
    untrack(() => {
      const target = routeContainer ?? selectedContainer ?? list[0]?.name ?? null;
      if (target && target !== selectedContainer) {
        selectedContainer = target;
        fileStore.refresh(target).catch((e) => toastStore.setError(e));
      }
    });
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
