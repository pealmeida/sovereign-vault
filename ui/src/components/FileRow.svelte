<script lang="ts">
  import { Eye, Download, Trash2 } from '@lucide/svelte';
  import type { FileInfo } from '../lib/types';
  import ModePill from './ModePill.svelte';
  import { formatBytes, formatDate } from '../lib/formatters';
  import { fileStore } from '../stores/files.svelte';
  import { toastStore } from '../stores/toast.svelte';
  import { confirm } from '@tauri-apps/plugin-dialog';

  let {
    file,
    container,
    onPreview,
  }: { file: FileInfo; container: string; onPreview: (f: FileInfo) => void } = $props();

  async function doDelete() {
    const ok = await confirm(`Delete "${file.name}"? This cannot be undone.`, {
      title: 'Delete file',
      kind: 'warning',
    });
    if (!ok) return;
    try {
      await fileStore.remove(container, file.name);
      toastStore.setNotice(`"${file.name}" deleted.`);
    } catch (e) {
      toastStore.setError(e);
    }
  }

  async function doDownload() {
    try {
      const dest = await fileStore.export(container, file.name);
      if (!dest) return;
      toastStore.setNotice(`Saved to ${dest}`);
    } catch (e) {
      toastStore.setError(e);
    }
  }
</script>

<tr class="vault-table-row">
  <td class="item-cell">
    <span class="item-name">{file.name}</span>
    <span style="color:var(--muted);font-size:0.8rem">{container}</span>
  </td>
  <td><ModePill mode={file.mode} /></td>
  <td style="color:var(--muted)">{formatBytes(file.byteSize)}</td>
  <td style="color:var(--muted)">{formatDate(file.modifiedAt)}</td>
  <td>
    <div style="display:flex;gap:0.4rem">
      <button class="ghost-button" title="Preview" onclick={() => onPreview(file)}>
        <Eye size={13} />
      </button>
      <button class="ghost-button" title="Download" onclick={doDownload}>
        <Download size={13} />
      </button>
      <button class="ghost-button" style="color:var(--red)" title="Delete" onclick={doDelete}>
        <Trash2 size={13} />
      </button>
    </div>
  </td>
</tr>
