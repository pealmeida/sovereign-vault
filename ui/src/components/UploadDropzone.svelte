<script lang="ts">
  import { Upload } from '@lucide/svelte';
  import { fileStore } from '../stores/files.svelte';
  import { toastStore } from '../stores/toast.svelte';

  let { container }: { container: string } = $props();

  let dragging = $state(false);
  let fileInput: HTMLInputElement;

  async function uploadFiles(list: FileList | null) {
    if (!list || list.length === 0) return;
    for (const file of Array.from(list)) {
      try {
        const bytes = new Uint8Array(await file.arrayBuffer());
        await fileStore.write(container, file.name, bytes);
        toastStore.setNotice(`Uploaded "${file.name}".`);
      } catch (e) {
        toastStore.setError(e);
      }
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    dragging = false;
    uploadFiles(e.dataTransfer?.files ?? null);
  }
</script>

<div
  class="upload-dropzone"
  class:dragging
  role="region"
  aria-label="Drop files to upload"
  ondragover={(e) => { e.preventDefault(); dragging = true; }}
  ondragleave={() => dragging = false}
  ondrop={onDrop}
>
  <Upload size={20} style="color:var(--muted)" />
  <span style="color:var(--muted);font-size:0.85rem">Drop files here or</span>
  <button class="ghost-button" onclick={() => fileInput.click()}>Browse</button>
  <input
    type="file"
    multiple
    style="display:none"
    bind:this={fileInput}
    onchange={(e) => uploadFiles((e.target as HTMLInputElement).files)}
  />
</div>

<style>
  .upload-dropzone {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 1rem;
    border: 1px dashed var(--border);
    border-radius: var(--radius);
    cursor: default;
    transition: border-color 0.15s, background 0.15s;
  }
  .upload-dropzone.dragging {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
</style>
