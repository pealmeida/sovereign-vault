<script lang="ts">
  import { Copy, Check } from 'lucide-svelte';
  let { value, label = 'Copy' }: { value: string; label?: string } = $props();
  let copied = $state(false);
  async function doCopy() {
    await navigator.clipboard.writeText(value);
    copied = true;
    setTimeout(() => { copied = false; }, 2000);
  }
</script>

<button class="ghost-button" onclick={doCopy}>
  {#if copied}<Check size={14} />{:else}<Copy size={14} />{/if}
  {label}
</button>
