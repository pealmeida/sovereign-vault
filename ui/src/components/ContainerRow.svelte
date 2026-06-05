<script lang="ts">
  import { ChevronDown, ChevronRight, FolderOpen, Trash2 } from 'lucide-svelte';
  import type { ContainerInfo } from '../lib/types';
  import ModePill from './ModePill.svelte';
  import ContextMenu from './ContextMenu.svelte';
  import { containerStore } from '../stores/containers.svelte';
  import { toastStore } from '../stores/toast.svelte';
  import { push } from 'svelte-spa-router';
  import { confirm } from '@tauri-apps/plugin-dialog';

  let { container }: { container: ContainerInfo } = $props();

  let expanded = $state(false);
  let ctx = $state<{ x: number; y: number } | null>(null);

  async function doDelete() {
    const ok = await confirm(
      `Delete container "${container.name}" and all its files? This cannot be undone.`,
      { title: 'Delete container', kind: 'warning' },
    );
    if (!ok) return;
    try {
      await containerStore.remove(container.name);
      toastStore.setNotice(`Container "${container.name}" deleted.`);
    } catch (e) {
      toastStore.setError(e);
    }
  }

  function openFiles() {
    push(`/files/${encodeURIComponent(container.name)}`);
  }
</script>

<article class="vault-row">
  <div
    class="vault-summary"
    role="button"
    tabindex="0"
    onclick={() => expanded = !expanded}
    onkeydown={(e) => e.key === 'Enter' && (expanded = !expanded)}
    oncontextmenu={(e) => { e.preventDefault(); ctx = { x: e.clientX, y: e.clientY }; }}
  >
    {#if expanded}<ChevronDown size={15} />{:else}<ChevronRight size={15} />{/if}
    <FolderOpen size={16} style="color:var(--accent)" />
    <div class="vault-meta">
      <strong>{container.name}</strong>
      {#if container.description}<span style="color:var(--muted);font-size:0.85rem">{container.description}</span>{/if}
    </div>
    <span class="timestamp-chip">{container.fileCount} files</span>
    <ModePill mode={container.mode} />
  </div>

  {#if expanded}
    <div class="vault-contents">
      <button class="ghost-button" onclick={openFiles}>
        <FolderOpen size={14} /> Open in Files
      </button>
      <button class="ghost-button" style="color:var(--red)" onclick={doDelete}>
        <Trash2 size={14} /> Delete
      </button>
    </div>
  {/if}
</article>

{#if ctx}
  <ContextMenu
    x={ctx.x}
    y={ctx.y}
    items={[
      { label: 'Open in Files', onClick: openFiles },
      { label: 'Delete', danger: true, onClick: doDelete },
    ]}
    onClose={() => ctx = null}
  />
{/if}
