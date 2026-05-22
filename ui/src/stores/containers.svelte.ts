import { invoke } from '../lib/tauri';
import type { ContainerInfo, Mode } from '../lib/types';

let containers = $state<ContainerInfo[]>([]);
let loading = $state(false);

export const containerStore = {
  get list() { return containers; },
  get loading() { return loading; },

  async refresh() {
    loading = true;
    try {
      containers = await invoke<ContainerInfo[]>('vault_list_containers');
    } finally {
      loading = false;
    }
  },

  async create(name: string, mode: Mode, description: string) {
    await invoke<void>('vault_create_container', { name, mode, description });
    await this.refresh();
  },

  async remove(name: string) {
    await invoke<void>('vault_delete_container', { name });
    await this.refresh();
  },
};
