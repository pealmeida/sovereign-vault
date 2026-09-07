import type { Component } from 'svelte';
import {
  FolderLock,
  Files,
  Settings2,
  ScrollText,
  Radar,
} from '@lucide/svelte';

/**
 * Single source of truth for route presentation metadata.
 *
 * App.svelte owns the route-to-component mapping; this registry is for
 * navigation labels, icons, and page headers so adding a route cannot silently
 * produce a missing title.
 */
export interface RouteMeta {
  path: string;
  label: string;
  icon: Component;
  eyebrow: string;
  title: string;
}

export const routes: RouteMeta[] = [
  {
    path: '/vault',
    label: 'Vault',
    icon: FolderLock,
    eyebrow: 'Agent storage',
    title: 'Secure data categories',
  },
  {
    path: '/files',
    label: 'Files',
    icon: Files,
    eyebrow: 'Vault files',
    title: 'Encrypted file registry',
  },
  {
    path: '/scans',
    label: 'Scans',
    icon: Radar,
    eyebrow: 'Sensitive data',
    title: 'Scans and remediation',
  },
  {
    path: '/logs',
    label: 'Logs',
    icon: ScrollText,
    eyebrow: 'Audit trail',
    title: 'Signed activity log',
  },
  {
    path: '/settings',
    label: 'Settings',
    icon: Settings2,
    eyebrow: 'Preferences',
    title: 'Storage and runtime',
  },
];

/** Map from path prefix to route metadata. */
export const routeByPath = new Map<string, RouteMeta>(
  routes.map((r) => [r.path, r])
);

/** Resolve the route metadata that best matches the current location. */
export function resolveRouteMeta(location: string): RouteMeta {
  // Exact match first.
  const exact = routeByPath.get(location);
  if (exact) return exact;

  // Longest-prefix match, so `/files/container/foo` resolves to `/files`.
  let best: RouteMeta | undefined;
  for (const route of routes) {
    if (
      location.startsWith(route.path) &&
      (!best || route.path.length > best.path.length)
    ) {
      best = route;
    }
  }

  // Default to Vault so the header is never empty. routes is non-empty, so the
  // cast is safe.
  return best ?? (routes[0] as RouteMeta);
}
