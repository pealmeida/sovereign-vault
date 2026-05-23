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
