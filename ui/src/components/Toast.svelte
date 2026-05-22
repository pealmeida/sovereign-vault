<script lang="ts">
  import { toastStore } from '../stores/toast.svelte';
</script>

{#if toastStore.notice}
  <div class="toast toast-success">{toastStore.notice}</div>
{/if}
{#if toastStore.error}
  <div class="toast toast-error">{toastStore.error}</div>
{/if}
