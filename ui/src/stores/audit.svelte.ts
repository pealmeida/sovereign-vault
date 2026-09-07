import { invoke } from '../lib/tauri';
import type { AuditEvent, VerifyReport, AuditTailResponse } from '../lib/types';

let events = $state<AuditEvent[]>([]);
let verifyReport = $state<VerifyReport | null>(null);
let malformedSkipped = $state(0);
let total = $state(0);
let loading = $state(false);
let error = $state<string | null>(null);
let actionFilter = $state<string | null>(null);
let decisionFilter = $state<string | null>(null);
let pageSize = $state(25);
let page = $state(0);

const allActions = $derived(
  Array.from(new Set(events.map((e) => e.action))).sort()
);
const allDecisions = $derived(
  Array.from(new Set(events.map((e) => e.decision))).sort()
);

const filteredEvents = $derived(
  events.filter((e) => {
    if (actionFilter && e.action !== actionFilter) return false;
    if (decisionFilter && e.decision !== decisionFilter) return true;
    return true;
  })
);

const pageEvents = $derived(
  filteredEvents.slice(page * pageSize, (page + 1) * pageSize)
);

const pageCount = $derived(
  Math.max(1, Math.ceil(filteredEvents.length / pageSize))
);

export const auditStore = {
  get events() { return events; },
  get verifyReport() { return verifyReport; },
  get malformedSkipped() { return malformedSkipped; },
  get total() { return total; },
  get loading() { return loading; },
  get error() { return error; },
  get actionFilter() { return actionFilter; },
  get decisionFilter() { return decisionFilter; },
  get pageSize() { return pageSize; },
  get page() { return page; },
  get allActions() { return allActions; },
  get allDecisions() { return allDecisions; },
  get filteredEvents() { return filteredEvents; },
  get pageEvents() { return pageEvents; },
  get pageCount() { return pageCount; },

  setActionFilter(value: string | null) {
    actionFilter = value;
    page = 0;
  },

  setDecisionFilter(value: string | null) {
    decisionFilter = value;
    page = 0;
  },

  setPageSize(value: number) {
    pageSize = value;
    page = 0;
  },

  setPage(value: number) {
    page = Math.max(0, Math.min(value, pageCount - 1));
  },

  async refresh() {
    loading = true;
    error = null;
    try {
      const [tail, report] = await Promise.all([
        invoke<AuditTailResponse>('audit_tail', { limit: 10000, offset: 0 }),
        invoke<VerifyReport>('audit_verify'),
      ]);
      events = tail.events;
      malformedSkipped = tail.malformed_skipped;
      total = tail.events.length;
      verifyReport = report;
      page = 0;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  },

  clear() {
    events = [];
    verifyReport = null;
    malformedSkipped = 0;
    total = 0;
    error = null;
    page = 0;
  },
};
