export type Custody = 'OsKeychain' | 'Passphrase' | 'Recovery';

export type Mode = 'DIRECT' | 'APPROVAL' | 'OTP' | 'ANONYMIZED' | 'ZKP' | 'NATIVE';

export interface ContainerInfo {
  name: string;
  mode: Mode;
  fileCount: number;
  description?: string | null;
}

export interface FileInfo {
  name: string;
  byteSize: number;
  modifiedAt: string;
  mode: Mode;
}

export interface VaultStatus {
  initialized: boolean;
  unlocked: boolean;
  custody: Custody | null;
  has_keychain_entry: boolean;
  has_passphrase_salt: boolean;
  has_recovery_bundle: boolean;
  has_keyring: boolean;
}

export interface VaultInitResponse {
  recovery_phrase: string;
}

export interface ApprovalPrompt {
  id: number;
  action: string;
  container: string | null;
  file_name: string | null;
  mode: string | null;
  byte_size: number | null;
  otp_code: string | null;
}

export interface McpStatus {
  running: boolean;
  pairing_secret: string | null;
  ws_url: string;
  http_url: string;
}

export interface AgentScope {
  container_glob: string;
  actions: string[];
  mode_ceiling?: string | null;
}

export interface AgentInfo {
  agent_id: string;
  name: string;
  created_at: string;
  expires_at: string | null;
  revoked: boolean;
  scopes: AgentScope[];
}

export interface AgentCreated {
  agent_id: string;
  token: string;
}

export interface TransitKeyInfo {
  name: string;
  version: number;
}

export interface SigningKeyInfo {
  name: string;
  version: number;
  public_b64: string;
}

export interface BrokerAllow {
  host: string;
  path_prefix: string;
  methods: string[];
  allow_private_ip?: boolean;
}

export type BrokerInjection =
  | 'bearer_auth'
  | { header: { name: string } };

export interface BrokerSecretInfo {
  name: string;
  allow: BrokerAllow[];
  injection: BrokerInjection;
}
