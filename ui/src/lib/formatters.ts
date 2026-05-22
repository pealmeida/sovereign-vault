import type { Mode } from './types';

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

export function modeClass(mode: Mode): string {
  const map: Record<Mode, string> = {
    DIRECT: 'mode-direct',
    APPROVAL: 'mode-approval',
    OTP: 'mode-otp',
    ANONYMIZED: 'mode-anon',
    ZKP: 'mode-zkp',
    NATIVE: 'mode-native',
  };
  return map[mode] ?? 'mode-direct';
}
