<script lang="ts">
  import { onMount } from 'svelte';

  let version = $state('loading…');

  onMount(async () => {
    try {
      // Tauri 2's invoke is at @tauri-apps/api/core. Imported lazily so the
      // Svelte build doesn't fail when running outside Tauri.
      const { invoke } = await import('@tauri-apps/api/core');
      version = await invoke<string>('app_version');
    } catch {
      version = 'browser-mode';
    }
  });
</script>

<main>
  <h1>Sovereign Vault</h1>
  <p class="tagline">Vaults for AI Agents — Safeguarding Memory, Access, and Control.</p>
  <p class="version">v{version}</p>
  <p class="status">Pre-alpha — see <a href="https://github.com/pealmeida/sovereign-vault">README</a> for status.</p>
</main>

<style>
  :global(body) {
    margin: 0;
    background: #0e1116;
    color: #e6edf3;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  }
  main {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 2rem;
    text-align: center;
  }
  h1 { font-size: 2.4rem; margin: 0 0 0.5rem; }
  .tagline { opacity: 0.85; max-width: 30rem; }
  .version { opacity: 0.6; font-family: ui-monospace, monospace; margin-top: 1.5rem; }
  .status { opacity: 0.5; font-size: 0.85rem; margin-top: 2rem; }
  a { color: #6cb2ff; }
</style>
