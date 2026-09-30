/// Keychain facts arrive from the desktop as tri-state: true, false, or
/// null when this process has not observed the keychain yet
/// (perf/keychain-reads). Unknown must never render as absence or failure.

/// "OS Keychain entry" cell: unknown stays Unknown, never "None".
export function keychainEntryLabel(hasEntry: boolean | null): string {
  if (hasEntry === true) return 'Present';
  if (hasEntry === false) return 'None';
  return 'Unknown';
}

/// "OS Keychain backend" cell: the backend name is only shown when the
/// availability was actually observed.
export function keychainBackendLabel(
  available: boolean | null,
  backend: string,
  error: string | null
): string {
  if (available === true) return backend;
  if (available === false) return error ?? 'Unavailable';
  return 'Unknown';
}

/// A locked screen must keep offering the keychain unlock when availability
/// is simply unobserved: unknown is not broken.
export function keychainUnlockOffered(available: boolean | null): boolean {
  return available ?? true;
}
