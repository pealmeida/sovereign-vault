<script lang="ts">
  import { X, Download } from 'lucide-svelte';
  import type { FileInfo } from '../lib/types';
  import { fileStore } from '../stores/files.svelte';
  import { toastStore } from '../stores/toast.svelte';
  import { formatBytes } from '../lib/formatters';
  import { save } from '@tauri-apps/plugin-dialog';
  import { writeFile } from '@tauri-apps/plugin-fs';

  const MAX_PREVIEW_BYTES = 256 * 1024;

  let {
    file,
    container,
    onClose,
  }: { file: FileInfo; container: string; onClose: () => void } = $props();

  let content = $state<string | null>(null);
  let loading = $state(true);
  let tooLarge = $state(false);
  let rawBytes = $state<Uint8Array | null>(null);

  $effect(() => {
    loading = true;
    content = null;
    tooLarge = false;
    fileStore.read(container, file.name).then((bytes) => {
      rawBytes = bytes;
      if (bytes.length > MAX_PREVIEW_BYTES) {
        tooLarge = true;
      } else {
        content = new TextDecoder().decode(bytes);
      }
      loading = false;
    }).catch((e) => {
      toastStore.setError(e);
      loading = false;
    });
  });

  async function doDownload() {
    if (!rawBytes) return;
    try {
      const dest = await save({ defaultPath: file.name });
      if (!dest) return;
      await writeFile(dest, rawBytes);
      toastStore.setNotice(`Saved to ${dest}`);
    } catch (e) {
      toastStore.setError(e);
    }
  }
</script>

<div class="modal-shell" role="dialog" aria-modal="true">
  <div class="modal-card panel-card" style="max-width:680px;width:100%;max-height:80vh;display:flex;flex-direction:column">
    <div class="panel-header">
      <div>
        <p class="eyebrow">{container}</p>
        <h3 style="font-family:var(--font-mono);font-size:0.9rem">{file.name}</h3>
      </div>
      <div style="display:flex;gap:0.5rem">
        <button class="ghost-button" onclick={doDownload}><Download size={14} /></button>
        <button class="ghost-button" onclick={onClose}><X size={16} /></button>
      </div>
    </div>

    <p style="color:var(--muted);font-size:0.8rem;margin-bottom:0.75rem">
      {formatBytes(file.byteSize)}
    </p>

    <div style="overflow:auto;flex:1">
      {#if loading}
        <p style="color:var(--muted)">Loading…</p>
      {:else if tooLarge}
        <p style="color:var(--yellow)">
          File exceeds 256 KB preview limit. Use Download to save locally.
        </p>
      {:else if content !== null}
        <pre style="font-family:var(--font-mono);font-size:0.82rem;color:var(--text);white-space:pre-wrap;word-break:break-all">{content}</pre>
      {/if}
    </div>
  </div>
</div>
