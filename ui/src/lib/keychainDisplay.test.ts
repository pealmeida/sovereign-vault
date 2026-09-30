import { describe, expect, it } from 'vitest';

import {
  keychainBackendLabel,
  keychainEntryLabel,
  keychainUnlockOffered,
} from './keychainDisplay';

describe('keychain tri-state display (perf/keychain-reads)', () => {
  it('keeps an unobserved keychain entry as Unknown, never None', () => {
    expect(keychainEntryLabel(null)).toBe('Unknown');
    expect(keychainEntryLabel(true)).toBe('Present');
    expect(keychainEntryLabel(false)).toBe('None');
  });

  it('does not render unobserved availability as Unavailable', () => {
    expect(keychainBackendLabel(null, 'macOS Keychain', null)).toBe('Unknown');
    expect(keychainBackendLabel(true, 'macOS Keychain', null)).toBe('macOS Keychain');
    expect(keychainBackendLabel(false, 'macOS Keychain', 'boom')).toBe('boom');
    expect(keychainBackendLabel(false, 'macOS Keychain', null)).toBe('Unavailable');
  });

  it('offers the keychain unlock when availability is unknown', () => {
    expect(keychainUnlockOffered(null)).toBe(true);
    expect(keychainUnlockOffered(true)).toBe(true);
    expect(keychainUnlockOffered(false)).toBe(false);
  });
});
