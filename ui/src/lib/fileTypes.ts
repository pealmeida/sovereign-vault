/**
 * File-type detection for the embedded viewer.
 *
 * Maps a file name extension to a viewer kind and a MIME type. The viewer
 * kind is what FileViewerModal switches on to pick the correct renderer.
 */

export type ViewerKind =
  | 'pdf'
  | 'image'
  | 'video'
  | 'audio'
  | 'markdown'
  | 'code'
  | 'text'
  | 'office'
  | 'binary';

export interface FileTypeInfo {
  kind: ViewerKind;
  mime: string;
  /** highlight.js language hint when kind === 'code' */
  language?: string;
}

const map: Record<string, FileTypeInfo> = {
  // PDF
  pdf: { kind: 'pdf', mime: 'application/pdf' },

  // Images
  png:  { kind: 'image', mime: 'image/png' },
  jpg:  { kind: 'image', mime: 'image/jpeg' },
  jpeg: { kind: 'image', mime: 'image/jpeg' },
  gif:  { kind: 'image', mime: 'image/gif' },
  webp: { kind: 'image', mime: 'image/webp' },
  bmp:  { kind: 'image', mime: 'image/bmp' },
  ico:  { kind: 'image', mime: 'image/x-icon' },
  svg:  { kind: 'image', mime: 'image/svg+xml' },
  avif: { kind: 'image', mime: 'image/avif' },

  // Video
  mp4:  { kind: 'video', mime: 'video/mp4' },
  webm: { kind: 'video', mime: 'video/webm' },
  ogv:  { kind: 'video', mime: 'video/ogg' },
  mov:  { kind: 'video', mime: 'video/quicktime' },

  // Audio
  mp3:  { kind: 'audio', mime: 'audio/mpeg' },
  wav:  { kind: 'audio', mime: 'audio/wav' },
  ogg:  { kind: 'audio', mime: 'audio/ogg' },
  flac: { kind: 'audio', mime: 'audio/flac' },
  m4a:  { kind: 'audio', mime: 'audio/mp4' },
  aac:  { kind: 'audio', mime: 'audio/aac' },

  // Markdown
  md:       { kind: 'markdown', mime: 'text/markdown' },
  markdown: { kind: 'markdown', mime: 'text/markdown' },
  mdx:      { kind: 'markdown', mime: 'text/markdown' },

  // Code (with highlight.js language hints)
  js:    { kind: 'code', mime: 'text/javascript', language: 'javascript' },
  mjs:   { kind: 'code', mime: 'text/javascript', language: 'javascript' },
  cjs:   { kind: 'code', mime: 'text/javascript', language: 'javascript' },
  ts:    { kind: 'code', mime: 'text/typescript', language: 'typescript' },
  tsx:   { kind: 'code', mime: 'text/typescript', language: 'typescript' },
  jsx:   { kind: 'code', mime: 'text/javascript', language: 'javascript' },
  py:    { kind: 'code', mime: 'text/x-python',   language: 'python' },
  rs:    { kind: 'code', mime: 'text/x-rust',     language: 'rust' },
  go:    { kind: 'code', mime: 'text/x-go',       language: 'go' },
  java:  { kind: 'code', mime: 'text/x-java',     language: 'java' },
  c:     { kind: 'code', mime: 'text/x-c',        language: 'c' },
  h:     { kind: 'code', mime: 'text/x-c',        language: 'c' },
  cpp:   { kind: 'code', mime: 'text/x-c++',      language: 'cpp' },
  cs:    { kind: 'code', mime: 'text/x-csharp',   language: 'csharp' },
  rb:    { kind: 'code', mime: 'text/x-ruby',     language: 'ruby' },
  php:   { kind: 'code', mime: 'text/x-php',      language: 'php' },
  swift: { kind: 'code', mime: 'text/x-swift',    language: 'swift' },
  kt:    { kind: 'code', mime: 'text/x-kotlin',   language: 'kotlin' },
  sh:    { kind: 'code', mime: 'text/x-sh',       language: 'bash' },
  bash:  { kind: 'code', mime: 'text/x-sh',       language: 'bash' },
  zsh:   { kind: 'code', mime: 'text/x-sh',       language: 'bash' },
  ps1:   { kind: 'code', mime: 'text/x-powershell', language: 'powershell' },
  sql:   { kind: 'code', mime: 'text/x-sql',      language: 'sql' },
  html:  { kind: 'code', mime: 'text/html',       language: 'xml' },
  xml:   { kind: 'code', mime: 'text/xml',        language: 'xml' },
  css:   { kind: 'code', mime: 'text/css',        language: 'css' },
  scss:  { kind: 'code', mime: 'text/x-scss',     language: 'scss' },
  json:  { kind: 'code', mime: 'application/json', language: 'json' },
  yaml:  { kind: 'code', mime: 'text/yaml',       language: 'yaml' },
  yml:   { kind: 'code', mime: 'text/yaml',       language: 'yaml' },
  toml:  { kind: 'code', mime: 'text/x-toml',     language: 'ini' },
  ini:   { kind: 'code', mime: 'text/x-ini',      language: 'ini' },
  dockerfile: { kind: 'code', mime: 'text/x-dockerfile', language: 'dockerfile' },
  svelte: { kind: 'code', mime: 'text/x-svelte', language: 'xml' },

  // Plain text
  txt:  { kind: 'text', mime: 'text/plain' },
  log:  { kind: 'text', mime: 'text/plain' },
  csv:  { kind: 'text', mime: 'text/csv' },
  tsv:  { kind: 'text', mime: 'text/tab-separated-values' },

  // Office (not directly renderable — show info + download)
  docx: { kind: 'office', mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' },
  doc:  { kind: 'office', mime: 'application/msword' },
  xlsx: { kind: 'office', mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
  xls:  { kind: 'office', mime: 'application/vnd.ms-excel' },
  pptx: { kind: 'office', mime: 'application/vnd.openxmlformats-officedocument.presentationml.presentation' },
  ppt:  { kind: 'office', mime: 'application/vnd.ms-powerpoint' },
};

/** Get extension from filename, lowercased. Returns '' if none. */
export function getExtension(name: string): string {
  const lower = name.toLowerCase();
  const dot = lower.lastIndexOf('.');
  return dot > 0 ? lower.slice(dot + 1) : '';
}

/** Detect type info for a given file name. */
export function detectFileType(name: string): FileTypeInfo {
  // Special filenames without extension
  const lower = name.toLowerCase();
  if (lower === 'dockerfile' || lower.endsWith('/dockerfile')) {
    return map.dockerfile!;
  }
  if (lower === 'makefile' || lower === '.gitignore' || lower === '.env') {
    return { kind: 'text', mime: 'text/plain' };
  }

  const ext = getExtension(name);
  return map[ext] ?? { kind: 'binary', mime: 'application/octet-stream' };
}
