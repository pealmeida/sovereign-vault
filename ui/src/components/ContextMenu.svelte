<script lang="ts">
  interface MenuItem {
    label: string;
    onClick: () => void;
    danger?: boolean;
  }

  let {
    x,
    y,
    items,
    onClose,
  }: { x: number; y: number; items: MenuItem[]; onClose: () => void } = $props();
</script>

<div
  class="context-menu"
  style="left:{x}px;top:{y}px"
  role="menu"
>
  {#each items as item}
    <button
      class="ctx-item"
      class:danger={item.danger}
      role="menuitem"
      onclick={() => { item.onClick(); onClose(); }}
    >
      {item.label}
    </button>
  {/each}
</div>

<div class="ctx-backdrop" role="presentation" onclick={onClose}></div>

<style>
  .context-menu {
    position: fixed;
    z-index: 200;
    background: var(--surface-strong);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.25rem 0;
    min-width: 160px;
    box-shadow: var(--shadow);
  }
  .ctx-item {
    display: block;
    width: 100%;
    text-align: left;
    padding: 0.45rem 0.9rem;
    font-size: 0.85rem;
    background: none;
    border: none;
    color: var(--text);
    cursor: pointer;
  }
  .ctx-item:hover { background: var(--accent-soft); }
  .ctx-item.danger { color: var(--red); }
  .ctx-backdrop {
    position: fixed;
    inset: 0;
    z-index: 199;
  }
</style>
