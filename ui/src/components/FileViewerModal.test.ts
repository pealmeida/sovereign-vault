import { render, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { FileInfo } from '../lib/types';
import FileViewerModal from './FileViewerModal.svelte';

/// Tests for the file preview modal's load path.
///
/// # The bug these guard
///
/// A real audit log on a developer machine holds 27,075 reads of a single
/// 93,965-byte file, 99.8% of them under a second apart, peaking at ~28 reads
/// per second, all from this component.
///
/// The cause is prop IDENTITY. The load effect read `file.name`, but `file` is
/// a props object, so touching a field tracks the prop itself: a parent that
/// hands down a new object with the same name re-runs the effect and re-reads
/// the file. `reads once for a file whose props object is recreated with equal
/// values` is the test that catches it -- it fails against the original
/// component and passes once the identity is derived to primitives.
///
/// The other three pin the surrounding behaviour so a future fix cannot
/// "solve" the loop by never reloading at all.

const invokeMock = vi.fn();

vi.mock('../lib/tauri', () => ({
  invoke: (cmd: string, args?: Record<string, unknown>) => invokeMock(cmd, args),
}));

const FILE_BYTES = Array.from(new TextEncoder().encode('# hello\n\nsome markdown\n'));

function countReads(): number {
  return invokeMock.mock.calls.filter(([cmd]) => cmd === 'vault_read_file').length;
}

function props(name: string) {
  const file: FileInfo = {
    name,
    byteSize: FILE_BYTES.length,
    modifiedAt: '2026-01-01T00:00:00Z',
    mode: 'DIRECT',
  };
  return { file, container: 'personal', onClose: () => {} };
}

describe('FileViewerModal', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === 'vault_read_file') return Promise.resolve(FILE_BYTES);
      return Promise.resolve(null);
    });
  });

  it('reads the file once per mount', async () => {
    render(FileViewerModal, { props: props('notes.md') });

    await waitFor(() => expect(countReads()).toBeGreaterThan(0));
    // Leave the modal open long enough for a repeating read to show up. At the
    // rate seen in the audit log (~28/second) this window would accumulate
    // roughly seven reads.
    await new Promise((resolve) => setTimeout(resolve, 250));

    expect(countReads()).toBe(1);
  });

  it('does not re-read while the modal stays open', async () => {
    render(FileViewerModal, { props: props('notes.md') });

    await waitFor(() => expect(countReads()).toBe(1));
    await new Promise((resolve) => setTimeout(resolve, 400));

    expect(countReads()).toBe(1);
  });

  it('reads again, once, when a different file is shown', async () => {
    const { rerender } = render(FileViewerModal, { props: props('notes.md') });

    await waitFor(() => expect(countReads()).toBe(1));
    await rerender(props('other.md'));
    await waitFor(() => expect(countReads()).toBe(2));

    const readNames = invokeMock.mock.calls
      .filter(([cmd]) => cmd === 'vault_read_file')
      .map(([, args]) => (args as { fileName: string }).fileName);
    expect(readNames).toEqual(['notes.md', 'other.md']);
  });

  it('reads once for a file whose props object is recreated with equal values', async () => {
    // The parent holds the previewed file in `$state`. If something upstream
    // recreates that object with the same contents, an effect keyed on object
    // identity would reload on every recreation. This pins that a same-valued
    // prop does not cause a second read.
    const { rerender } = render(FileViewerModal, { props: props('notes.md') });

    await waitFor(() => expect(countReads()).toBe(1));
    await rerender(props('notes.md'));
    await new Promise((resolve) => setTimeout(resolve, 100));

    expect(countReads()).toBe(1);
  });
});
