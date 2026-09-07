/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// Vite + Tauri integration:
//  - Fixed port (Tauri's beforeDevCommand expects 1420)
//  - strictPort so we never bind a different port silently
//  - clearScreen false so Vite output stays visible alongside Tauri
export default defineConfig({
  plugins: [svelte()],
  // `browser` first so Vitest does not resolve Svelte to its SERVER build,
  // where `mount()` throws lifecycle_function_unavailable. Harmless for the
  // app build, which already resolves browser-first.
  resolve: {
    conditions: ['browser'],
  },
  clearScreen: false,
  test: {
    // happy-dom, not node: these tests mount real components and assert on the
    // reactive graph, which needs a DOM. happy-dom rather than jsdom because
    // jsdom 27 pulls a CJS package that require()s an ESM dependency, which
    // throws ERR_REQUIRE_ESM on Node 20 (require of ESM landed in Node 22).
    environment: 'happy-dom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.ts', 'src/**/*.svelte.test.ts'],
    // Don't hand stylesheets to jsdom's CSS parser. Components import real
    // stylesheets (e.g. highlight.js themes) and parsing them adds nothing to
    // these tests -- they assert behaviour, never computed style.
    css: false,
  },
  server: {
    port: 1420,
    strictPort: true,
  },
  build: {
    target: 'esnext',
    sourcemap: true,
  },
});
