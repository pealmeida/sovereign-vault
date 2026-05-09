import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// Vite + Tauri integration:
//  - Fixed port (Tauri's beforeDevCommand expects 1420)
//  - strictPort so we never bind a different port silently
//  - clearScreen false so Vite output stays visible alongside Tauri
export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  build: {
    target: 'esnext',
    sourcemap: true,
  },
});
