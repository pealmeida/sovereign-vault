<script lang="ts">
  import { X, Download, FileWarning, FileText } from 'lucide-svelte';
  import { onDestroy } from 'svelte';
  import { marked } from 'marked';
  import DOMPurify from 'dompurify';
  import hljs from 'highlight.js/lib/common';
  import 'highlight.js/styles/github-dark.css';

  import type { FileInfo } from '../lib/types';
  import { fileStore } from '../stores/files.svelte';
  import { toastStore } from '../stores/toast.svelte';
  import { formatBytes } from '../lib/formatters';
  import { detectFileType, type FileTypeInfo } from '../lib/fileTypes';
  import { save } from '@tauri-apps/plugin-dialog';
  import { writeFile } from '@tauri-apps/plugin-fs';

  // 5 MB upper bound for inline preview of any kind. Binary media (pdf/image/video/audio)
  // up to this size renders inline; larger files prompt to download.
  const MAX_PREVIEW_BYTES = 5 * 1024 * 1024;
  // Text/code/markdown decoded only up to 256 KB to keep the DOM snappy.
  const MAX_TEXT_BYTES = 256 * 1024;

  let {
    file,
    container,
    onClose,
  }: { file: FileInfo; container: string; onClose: () => void } = $props();

  let info = $derived<FileTypeInfo>(detectFileType(file.name));

  let loading = $state(true);
  let tooLarge = $state(false);

  let rawBytes = $state<Uint8Array | null>(null);
  let textContent = $state<string | null>(null);
  let htmlContent = $state<string | null>(null);
  let objectUrl = $state<string | null>(null);

  function revokeUrl() {
    if (objectUrl) {
      URL.revokeObjectURL(objectUrl);
      objectUrl = null;
    }
  }

  function buildObjectUrl(bytes: Uint8Array, mime: string): string {
    // Copy into a fresh ArrayBuffer so Blob accepts it cleanly across all envs.
    const blob = new Blob([new Uint8Array(bytes).buffer], { type: mime });
    return URL.createObjectURL(blob);
  }

  function renderMarkdown(text: string): string {
    const raw = marked.parse(text, { async: false }) as string;
    return DOMPurify.sanitize(raw, { USE_PROFILES: { html: true } });
  }

  function renderCode(text: string, language?: string): string {
    if (language && hljs.getLanguage(language)) {
      try {
        return hljs.highlight(text, { language, ignoreIllegals: true }).value;
      } catch {
        /* fall through */
      }
    }
    try {
      return hljs.highlightAuto(text).value;
    } catch {
      return escapeHtml(text);
    }
  }

  function escapeHtml(s: string): string {
    return s.replace(/[&<>"']/g, (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!)
    );
  }

  $effect(() => {
    // Re-run when file changes
    loading = true;
    tooLarge = false;
    textContent = null;
    htmlContent = null;
    revokeUrl();
    rawBytes = null;

    const currentName = file.name;

    fileStore
      .read(container, currentName)
      .then((bytes) => {
        // Bail if effect re-ran for a different file mid-flight
        if (file.name !== currentName) return;

        rawBytes = bytes;

        if (bytes.length > MAX_PREVIEW_BYTES) {
          tooLarge = true;
          loading = false;
          return;
        }

        const kind = info.kind;

        if (kind === 'pdf' || kind === 'image' || kind === 'video' || kind === 'audio') {
          objectUrl = buildObjectUrl(bytes, info.mime);
        } else if (
          kind === 'markdown' ||
          kind === 'code' ||
          kind === 'text'
        ) {
          if (bytes.length > MAX_TEXT_BYTES) {
            tooLarge = true;
          } else {
            const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
            textContent = text;
            if (kind === 'markdown') {
              htmlContent = renderMarkdown(text);
            } else if (kind === 'code') {
              htmlContent = renderCode(text, info.language);
            }
          }
        }
        // 'office' and 'binary' fall through — UI shows download prompt.
        loading = false;
      })
      .catch((e) => {
        if (file.name !== currentName) return;
        toastStore.setError(e);
        loading = false;
      });
  });

  onDestroy(revokeUrl);

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

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') onClose();
  }
</script>

<svelte:window onkeydown={onKeydown} />

<div class="modal-shell" role="dialog" aria-modal="true" aria-label="File preview">
  <div class="modal-card panel-card viewer-card">
    <div class="panel-header viewer-header">
      <div class="viewer-title">
        <p class="eyebrow">{container} · {info.kind}</p>
        <h3>{file.name}</h3>
        <span class="viewer-size">{formatBytes(file.byteSize)}</span>
      </div>
      <div class="viewer-actions">
        <button class="ghost-button" onclick={doDownload} title="Download">
          <Download size={14} /> Download
        </button>
        <button class="icon-button" onclick={onClose} title="Close">
          <X size={16} />
        </button>
      </div>
    </div>

    <div class="viewer-body">
      {#if loading}
        <div class="viewer-state">
          <p style="color:var(--muted)">Decrypting and loading…</p>
        </div>
      {:else if tooLarge}
        <div class="viewer-state">
          <FileWarning size={32} style="color:var(--yellow)" />
          <p><strong>File too large to preview inline.</strong></p>
          <p style="color:var(--muted);font-size:0.85rem">
            {formatBytes(file.byteSize)} exceeds the
            {info.kind === 'markdown' || info.kind === 'code' || info.kind === 'text'
              ? '256 KB text'
              : '5 MB media'} preview limit. Use Download to save and open in another app.
          </p>
        </div>

      {:else if info.kind === 'pdf' && objectUrl}
        <iframe class="viewer-iframe" src={objectUrl} title={file.name}></iframe>

      {:else if info.kind === 'image' && objectUrl}
        <div class="viewer-media">
          <img src={objectUrl} alt={file.name} />
        </div>

      {:else if info.kind === 'video' && objectUrl}
        <div class="viewer-media">
          <!-- svelte-ignore a11y_media_has_caption -->
          <video src={objectUrl} controls></video>
        </div>

      {:else if info.kind === 'audio' && objectUrl}
        <div class="viewer-media viewer-audio">
          <audio src={objectUrl} controls></audio>
        </div>

      {:else if info.kind === 'markdown' && htmlContent !== null}
        <div class="viewer-markdown">
          {@html htmlContent}
        </div>

      {:else if info.kind === 'code' && htmlContent !== null}
        <pre class="viewer-code hljs"><code>{@html htmlContent}</code></pre>

      {:else if info.kind === 'text' && textContent !== null}
        <pre class="viewer-text">{textContent}</pre>

      {:else if info.kind === 'office'}
        <div class="viewer-state">
          <FileText size={32} style="color:var(--accent)" />
          <p><strong>Office document</strong></p>
          <p style="color:var(--muted);font-size:0.85rem">
            Open in Word, Excel, or PowerPoint by downloading the file.
          </p>
          <button class="primary-button" onclick={doDownload}>
            <Download size={14} /> Download
          </button>
        </div>

      {:else}
        <div class="viewer-state">
          <FileWarning size={32} style="color:var(--muted)" />
          <p><strong>Binary file</strong></p>
          <p style="color:var(--muted);font-size:0.85rem">
            No inline viewer is registered for this file type. Download it to inspect with another tool.
          </p>
          <button class="primary-button" onclick={doDownload}>
            <Download size={14} /> Download
          </button>
        </div>
      {/if}
    </div>
  </div>
</div>

<style>
  .viewer-card {
    width: 100%;
    max-width: 960px;
    max-height: 88vh;
    display: flex;
    flex-direction: column;
    padding: 0;
    overflow: hidden;
  }

  .viewer-header {
    padding: 1rem 1.25rem;
    margin-bottom: 0;
    border-bottom: 1px solid var(--border);
    gap: 1rem;
  }

  .viewer-title {
    min-width: 0;
    flex: 1;
  }

  .viewer-title h3 {
    margin: 0.1rem 0 0;
    font-family: var(--font-mono);
    font-size: 0.92rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .viewer-size {
    display: inline-block;
    margin-top: 0.25rem;
    color: var(--muted);
    font-size: 0.78rem;
  }

  .viewer-actions {
    display: flex;
    gap: 0.5rem;
  }

  .viewer-body {
    flex: 1;
    min-height: 0;
    overflow: auto;
    display: flex;
    flex-direction: column;
  }

  .viewer-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 0.75rem;
    text-align: center;
    padding: 3rem 1.5rem;
    flex: 1;
  }
  .viewer-state p { margin: 0; }

  .viewer-iframe {
    flex: 1;
    width: 100%;
    border: 0;
    background: #fff;
    min-height: 60vh;
  }

  .viewer-media {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 0, 0, 0.35);
    padding: 1rem;
    min-height: 0;
  }
  .viewer-media img,
  .viewer-media video {
    max-width: 100%;
    max-height: 72vh;
    object-fit: contain;
    display: block;
  }
  .viewer-audio { padding: 2rem; }
  .viewer-audio audio { width: 100%; max-width: 520px; }

  .viewer-markdown {
    padding: 1.25rem 1.5rem;
    font-family: var(--font-body);
    color: var(--text);
    line-height: 1.6;
  }
  .viewer-markdown :global(h1),
  .viewer-markdown :global(h2),
  .viewer-markdown :global(h3),
  .viewer-markdown :global(h4) {
    font-family: var(--font-display);
    margin: 1.4em 0 0.4em;
    color: var(--text);
  }
  .viewer-markdown :global(h1) { font-size: 1.4rem; }
  .viewer-markdown :global(h2) { font-size: 1.2rem; }
  .viewer-markdown :global(h3) { font-size: 1.05rem; }
  .viewer-markdown :global(p) { margin: 0.6em 0; }
  .viewer-markdown :global(a) { color: var(--accent); }
  .viewer-markdown :global(code) {
    font-family: var(--font-mono);
    font-size: 0.85em;
    background: rgba(98, 242, 255, 0.08);
    padding: 0.1em 0.35em;
    border-radius: 3px;
    color: var(--accent);
  }
  .viewer-markdown :global(pre) {
    background: rgba(0, 0, 0, 0.4);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.9rem 1rem;
    overflow: auto;
  }
  .viewer-markdown :global(pre code) {
    background: transparent;
    color: var(--text);
    padding: 0;
  }
  .viewer-markdown :global(blockquote) {
    border-left: 3px solid var(--accent);
    padding-left: 1rem;
    color: var(--muted);
    margin: 0.8em 0;
  }
  .viewer-markdown :global(table) {
    width: 100%;
    border-collapse: collapse;
    margin: 0.8em 0;
  }
  .viewer-markdown :global(th),
  .viewer-markdown :global(td) {
    border: 1px solid var(--border);
    padding: 0.45rem 0.7rem;
    text-align: left;
  }
  .viewer-markdown :global(img) {
    max-width: 100%;
    border-radius: var(--radius-sm);
  }

  .viewer-code {
    margin: 0;
    padding: 1.25rem 1.5rem;
    font-family: var(--font-mono);
    font-size: 0.82rem;
    line-height: 1.55;
    background: #0d1117;
    color: var(--text);
    overflow: auto;
    flex: 1;
  }

  .viewer-text {
    margin: 0;
    padding: 1.25rem 1.5rem;
    font-family: var(--font-mono);
    font-size: 0.82rem;
    line-height: 1.55;
    color: var(--text);
    white-space: pre-wrap;
    word-break: break-word;
    overflow: auto;
    flex: 1;
  }
</style>
