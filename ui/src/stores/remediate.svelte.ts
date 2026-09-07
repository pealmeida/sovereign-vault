import { invoke } from '../lib/tauri';
import type { IngestStatus, IngestView, PlanView, RestoreView } from '../lib/types';

export type FileTreatment = 'in-place' | 'vaulted';

export interface ManagedFileRow {
  plan_id: string;
  path: string;
  manifest: string | null;
  identity_enforced: boolean;
}

let plans = $state<PlanView[]>([]);
let pendingPlan = $state<PlanView | null>(null);
let busy = $state(false);
let error = $state<string | null>(null);

/// File treatment, keyed by the finding's relative path. Vaulting one file
/// changes the treatment of every finding inside it — and NOTHING else: the
/// row stays in "needs action", the counts stay, and the rotation reminder
/// stays visible. Vaulted is never a finished state (ADR-0020).
let treatments = $state<Record<string, FileTreatment>>({});

/// Eligibility refusals from the backend, keyed by path, shown verbatim.
let refusals = $state<Record<string, string>>({});

/// Ingestion failures from the backend, keyed by path, shown verbatim.
let failures = $state<Record<string, string>>({});

/// Successfully ingested files, in order. Every row carries the rotation
/// reminder: the file is secured, the credential is still live.
let ingested = $state<ManagedFileRow[]>([]);

export const remediateStore = {
  get plans() { return plans; },
  get pendingPlan() { return pendingPlan; },
  get busy() { return busy; },
  get error() { return error; },
  get ingested() { return ingested; },

  treatmentFor(path: string): FileTreatment {
    return treatments[path] ?? 'in-place';
  },

  refusalFor(path: string): string | null {
    return refusals[path] ?? null;
  },

  failureFor(path: string): string | null {
    return failures[path] ?? null;
  },

  async refreshPlans() {
    plans = await invoke<PlanView[]>('remediate_plan_list');
  },

  /// Asks the backend to plan ingestion for one finding's file. A
  /// wholly-sensitive file opens the confirm dialog (built ONLY from the
  /// returned PlanView); a partly-sensitive file records the refusal reason
  /// verbatim and opens nothing.
  async planFile(scanId: string, findingPath: string, adapter: string): Promise<PlanView> {
    busy = true;
    error = null;
    try {
      const view = await invoke<PlanView>('remediate_plan_file', {
        scan_id: scanId,
        finding_path: findingPath,
        adapter,
      });
      if (view.eligibility === 'wholly-sensitive') {
        pendingPlan = view;
      } else {
        refusals = { ...refusals, [findingPath]: view.eligibility };
        pendingPlan = null;
      }
      return view;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
      throw e;
    } finally {
      busy = false;
    }
  },

  cancelPendingPlan() {
    pendingPlan = null;
  },

  /// Executes the pending plan. On success the file's treatment becomes
  /// 'vaulted' — one column, nothing else moves — and the file joins the
  /// managed list with its rotation reminder attached.
  async executePending(): Promise<IngestView | null> {
    const plan = pendingPlan;
    if (!plan) return null;
    busy = true;
    error = null;
    try {
      const view = await invoke<IngestView>('remediate_execute', {
        plan_id: plan.plan_id,
        confirm_digest: plan.confirm_digest,
      });
      if (view.status === 'ingested') {
        treatments = { ...treatments, [plan.path]: 'vaulted' };
        const { [plan.path]: _cleared, ...restFailures } = failures;
        failures = restFailures;
        ingested = [
          ...ingested,
          {
            plan_id: plan.plan_id,
            path: plan.path,
            manifest: view.manifest,
            identity_enforced: view.identity_enforced,
          },
        ];
      } else {
        failures = {
          ...failures,
          [plan.path]: view.reason ?? `Ingestion did not complete (${view.status}).`,
        };
      }
      pendingPlan = null;
      return view;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
      throw e;
    } finally {
      busy = false;
    }
  },

  /// Conflict-checked restore: the backend compares content and refuses if
  /// the file changed after the rewrite. Nothing is silently overwritten.
  async restore(planId: string): Promise<RestoreView> {
    busy = true;
    error = null;
    try {
      const view = await invoke<RestoreView>('remediate_restore', { plan_id: planId });
      if (view.restored) {
        // The file is back in the tree; treatment reverts and the row leaves
        // the managed list. The rotation reminder is unaffected: restoring
        // bytes never revokes a credential.
        const row = ingested.find((r) => r.plan_id === planId);
        if (row) {
          treatments = { ...treatments, [row.path]: 'in-place' };
        }
        ingested = ingested.filter((r) => r.plan_id !== planId);
      }
      return view;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
      throw e;
    } finally {
      busy = false;
    }
  },
};

export type { IngestStatus };
