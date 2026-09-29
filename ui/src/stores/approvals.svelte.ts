import { invoke } from '../lib/tauri';
import type { ApprovalPrompt } from '../lib/types';

let queue = $state<ApprovalPrompt[]>([]);

export const approvalStore = {
  get queue() { return queue; },

  push(prompt: ApprovalPrompt) {
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

  /** Bring one request to the front (tray "Review…", ADR-0025 §7.2). */
  focus(id: number) {
    const idx = queue.findIndex((p) => p.id === id);
    const prompt = queue[idx];
    if (idx > 0 && prompt) {
      queue.splice(idx, 1);
      queue = [prompt, ...queue];
    }
  },

  async respond(id: number, approved: boolean, otpCode?: string) {
    await invoke<void>('approval_respond', {
      id,
      approved,
      otp_code: otpCode ?? null,
    });
    this.remove(id);
  },
};
