import { invoke } from '../lib/tauri';
import type { AgentInfo, AgentCreated } from '../lib/types';

let agents = $state<AgentInfo[]>([]);

export const agentsStore = {
  get agents() { return agents; },

  async refresh() {
    agents = await invoke<AgentInfo[]>('agent_list');
  },

  async create(name: string): Promise<AgentCreated> {
    const created = await invoke<AgentCreated>('agent_create', { name });
    await this.refresh();
    return created;
  },

  async revoke(agentId: string) {
    await invoke<void>('agent_revoke', { agentId });
    await this.refresh();
  },
};
