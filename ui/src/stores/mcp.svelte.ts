import { invoke } from '../lib/tauri';
import type { McpStatus } from '../lib/types';

let status = $state<McpStatus | null>(null);
let cliBinary = $state('<path-to-sovereign-vault>');

function makeStdioConfig(bin: string) {
  return JSON.stringify(
    { mcpServers: { sovereign_vault: { command: bin, args: ['mcp-stdio'] } } },
    null,
    2
  );
}

export const mcpStore = {
  get status() { return status; },
  get claudeConfig() { return makeStdioConfig(cliBinary); },
  get cursorConfig() { return makeStdioConfig(cliBinary); },
  get continueConfig() {
    return JSON.stringify(
      {
        mcpServerConfigs: [
          { transport: { type: 'stdio', command: cliBinary, args: ['mcp-stdio'] } },
        ],
      },
      null,
      2
    );
  },

  async refresh() {
    status = await invoke<McpStatus>('mcp_status');
    try {
      cliBinary = await invoke<string>('cli_binary_path');
    } catch {
      // command may not exist in all builds; keep default placeholder
    }
  },
};
