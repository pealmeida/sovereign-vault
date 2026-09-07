import { invoke } from '../lib/tauri';
import { listen, type Event } from '@tauri-apps/api/event';
import type { VaultStatus, Custody, VaultInitResponse, SessionStatus } from '../lib/types';

let status = $state<VaultStatus | null>(null);
let recoveryPhrase = $state('');
let gatewayWarning = $state<string | undefined>(undefined);
let loading = $state(false);
let session = $state<SessionStatus | null>(null);
let sessionPoll: ReturnType<typeof setInterval> | null = null;
let autoLockUnlisten: (() => void) | null = null;

/** Convert remaining seconds into a compact 'Xm Ys' or 'Xs' display. */
function formatDuration(totalSeconds: number | null): string | null {
  if (totalSeconds === null || totalSeconds < 0) return null;
  if (totalSeconds === 0) return '0s';
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

function handleAutoLock(reason: string) {
  stopSessionPolling();
  const message = reason === 'session-cap'
    ? 'Vault locked: maximum unlocked session duration reached.'
    : 'Vault locked: idle timeout reached.';
  import('../stores/toast.svelte').then(({ toastStore }) => {
    toastStore.setError(message, 8000);
  });
  vaultStore.refresh().catch(() => {});
}

function startSessionPolling() {
  if (typeof window === 'undefined') return;
  stopSessionPolling();
  void vaultStore.refreshSession();
  sessionPoll = setInterval(() => {
    vaultStore.refreshSession().catch(() => {});
  }, 5000);

  if (!autoLockUnlisten) {
    listen<string>('vault://auto-lock', (event: Event<string>) => {
      handleAutoLock(event.payload);
    }).then((unlisten) => {
      autoLockUnlisten = unlisten;
    }).catch(() => {});
  }
}

function stopSessionPolling() {
  if (sessionPoll) {
    clearInterval(sessionPoll);
    sessionPoll = null;
  }
  session = null;
}

export const vaultStore = {
  get status() { return status; },
  get recoveryPhrase() { return recoveryPhrase; },
  get gatewayWarning() { return gatewayWarning; },
  get loading() { return loading; },
  get session() { return session; },
  get idleLabel() { return formatDuration(session?.idle_remaining_secs ?? null); },
  get sessionLabel() { return formatDuration(session?.session_remaining_secs ?? null); },

  clearRecoveryPhrase() { recoveryPhrase = ''; },
  clearGatewayWarning() { gatewayWarning = undefined; },

  async refresh() {
    status = await invoke<VaultStatus>('vault_status');
    if (status?.unlocked && !sessionPoll) {
      startSessionPolling();
    } else if (!status?.unlocked && sessionPoll) {
      stopSessionPolling();
    }
  },

  async refreshSession() {
    session = await invoke<SessionStatus>('session_status');
    if (session?.locked) {
      stopSessionPolling();
      await this.refresh();
    }
  },

  async setLimits(idleSecs: number, absoluteSecs: number) {
    await invoke<void>('session_set_limits', { idle_secs: idleSecs, absolute_secs: absoluteSecs });
    await this.refreshSession();
  },

  async init(custody: Custody, passphrase: string | null) {
    loading = true;
    try {
      const res = await invoke<VaultInitResponse>('vault_init', { custody, passphrase });
      recoveryPhrase = res.recovery_phrase;
      gatewayWarning = res.gateway_warning;
      await this.refresh();
      startSessionPolling();
      return res.gateway_warning;
    } finally {
      loading = false;
    }
  },

  async unlock(custody: Custody, passphrase: string | null) {
    loading = true;
    try {
      await invoke<void>('vault_unlock', { custody, passphrase });
      await this.refresh();
      startSessionPolling();
    } finally {
      loading = false;
    }
  },

  async unlockRecovery(phrase: string) {
    loading = true;
    try {
      await invoke<void>('vault_unlock_recovery', { phrase });
      await this.refresh();
      startSessionPolling();
    } finally {
      loading = false;
    }
  },

  async lock() {
    try {
      await invoke<void>('vault_lock');
      stopSessionPolling();
      await this.refresh();
    } finally {
      recoveryPhrase = '';
      gatewayWarning = undefined;
    }
  },

  async changePassphrase(current: string, next: string) {
    loading = true;
    try {
      await invoke<void>('vault_change_passphrase', { current, new: next });
    } finally {
      loading = false;
    }
  },

  async rotateKey(passphrase: string | null) {
    loading = true;
    try {
      const res = await invoke<VaultInitResponse>('vault_rotate_key', { passphrase });
      recoveryPhrase = res.recovery_phrase;
      gatewayWarning = res.gateway_warning;
      await this.refresh();
      return res.recovery_phrase;
    } finally {
      loading = false;
    }
  },

  async appVersion(): Promise<string> {
    return invoke<string>('app_version');
  },

  async openAuditFolder(): Promise<void> {
    await invoke<void>('open_audit_folder');
  },
};
