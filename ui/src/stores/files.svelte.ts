import { invoke } from '../lib/tauri';
import type { FileInfo } from '../lib/types';

let files = $state<FileInfo[]>([]);
let activeContainer = $state<string | null>(null);
let loading = $state(false);

export const fileStore = {
  get files() { return files; },
  get activeContainer() { return activeContainer; },
  get loading() { return loading; },

  async refresh(container: string) {
    activeContainer = container;
    loading = true;
    try {
      files = await invoke<FileInfo[]>('vault_list_files', { container });
    } finally {
      loading = false;
    }
  },

  async write(container: string, name: string, content: Uint8Array) {
    await invoke<void>('vault_write_file', {
      container,
      fileName: name,
      content: Array.from(content),
    });
    if (activeContainer === container) await this.refresh(container);
  },

  async read(container: string, name: string): Promise<Uint8Array> {
    const arr = await invoke<number[]>('vault_read_file', { container, fileName: name });
    return new Uint8Array(arr);
  },

  async remove(container: string, name: string) {
    await invoke<void>('vault_delete_file', { container, fileName: name });
    if (activeContainer === container) await this.refresh(container);
  },
};
