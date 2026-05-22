import { invoke as tauriInvoke } from '@tauri-apps/api/core';

export function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return tauriInvoke<T>(cmd, args);
}
