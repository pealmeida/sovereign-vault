import { invoke } from '../lib/tauri';
import type { WakePrompt } from '../lib/types';

let queue = $state<WakePrompt[]>([]);
let loaded = $state(false);

async function refresh() {
  const list = await invoke<WakePrompt[]>('wake_list');
  queue = list;
  loaded = true;
}

export const wakeStore = {
  get queue() { return queue; },
  get loaded() { return loaded; },

  push(prompt: WakePrompt) {
    const idx = queue.findIndex((p) => p.id === prompt.id);
    if (idx >= 0) {
      queue[idx] = prompt;
    } else {
      queue = [...queue, prompt];
    }
  },

  remove(id: number) {
    queue = queue.filter((p) => p.id !== id);
  },

  async refresh() {
    await refresh();
  },

  async respond(id: number, approved: boolean) {
    await invoke<void>('wake_respond', { id, approved });
    this.remove(id);
  },
};
