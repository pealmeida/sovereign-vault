import { invoke } from '../lib/tauri';
import type {
  TransitKeyInfo,
  SigningKeyInfo,
  BrokerSecretInfo,
  BrokerAllow,
} from '../lib/types';

let transitKeys = $state<TransitKeyInfo[]>([]);
let signingKeys = $state<SigningKeyInfo[]>([]);
let brokerSecrets = $state<BrokerSecretInfo[]>([]);
let brokerEnabled = $state(false);

export const brokerStore = {
  get transitKeys() { return transitKeys; },
  get signingKeys() { return signingKeys; },
  get brokerSecrets() { return brokerSecrets; },
  get brokerEnabled() { return brokerEnabled; },

  async refresh() {
    transitKeys = await invoke<TransitKeyInfo[]>('transit_list_keys');
    signingKeys = await invoke<SigningKeyInfo[]>('signing_list_keys');
    brokerEnabled = await invoke<boolean>('broker_enabled');
    brokerSecrets = brokerEnabled
      ? await invoke<BrokerSecretInfo[]>('broker_list_secrets')
      : [];
  },

  async createTransitKey(name: string) {
    await invoke<TransitKeyInfo>('transit_create_key', { name });
    await this.refresh();
  },

  async createSigningKey(name: string) {
    await invoke<SigningKeyInfo>('signing_create_key', { name });
    await this.refresh();
  },

  async createBrokerSecret(name: string, secret: string, allow: BrokerAllow[]) {
    await invoke<BrokerSecretInfo>('broker_create_secret', {
      name,
      secret,
      allow,
      injection: 'bearer_auth',
    });
    await this.refresh();
  },
};
