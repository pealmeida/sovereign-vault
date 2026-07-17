import { invoke } from '../lib/tauri';
import type { VaultStatus, Custody, VaultInitResponse } from '../lib/types';

let status = $state<VaultStatus | null>(null);
let recoveryPhrase = $state('');
let gatewayWarning = $state<string | undefined>(undefined);
let loading = $state(false);

export const vaultStore = {
  get status() { return status; },
  get recoveryPhrase() { return recoveryPhrase; },
  get gatewayWarning() { return gatewayWarning; },
  get loading() { return loading; },

  clearRecoveryPhrase() { recoveryPhrase = ''; },
  clearGatewayWarning() { gatewayWarning = undefined; },

  async refresh() {
    status = await invoke<VaultStatus>('vault_status');
  },

  async init(custody: Custody, passphrase: string | null) {
    loading = true;
    try {
      const res = await invoke<VaultInitResponse>('vault_init', { custody, passphrase });
      recoveryPhrase = res.recovery_phrase;
      gatewayWarning = res.gateway_warning;
      await this.refresh();
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
    } finally {
      loading = false;
    }
  },

  async unlockRecovery(phrase: string) {
    loading = true;
    try {
      await invoke<void>('vault_unlock_recovery', { phrase });
      await this.refresh();
    } finally {
      loading = false;
    }
  },

  async lock() {
    try {
      await invoke<void>('vault_lock');
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
