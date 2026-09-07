import { invoke } from '../lib/tauri';
import type { ScanReport, ScanSummary, ScanVerdict } from '../lib/types';

let currentReport = $state<ScanReport | null>(null);
let history = $state<ScanSummary[]>([]);
let loading = $state(false);
let error = $state<string | null>(null);
let scanPath = $state('');
let packsInput = $state('');
let minConfidence = $state<'' | 'low' | 'medium' | 'high'>('');
let kindFilter = $state<string | null>(null);
let confidenceFilter = $state<'' | 'low' | 'medium' | 'high'>('');
let revealed = $state<Record<string, string>>({});

const allKinds = $derived(
  currentReport
    ? Array.from(new Set(currentReport.findings.map((f) => f.kind))).sort()
    : []
);

const filteredFindings = $derived(
  currentReport?.findings.filter((f) => {
    if (kindFilter && f.kind !== kindFilter) return false;
    if (confidenceFilter && f.confidence !== confidenceFilter) return false;
    return true;
  }) ?? []
);

export const scansStore = {
  get currentReport() { return currentReport; },
  get history() { return history; },
  get loading() { return loading; },
  get error() { return error; },
  get scanPath() { return scanPath; },
  get packsInput() { return packsInput; },
  get minConfidence() { return minConfidence; },
  get kindFilter() { return kindFilter; },
  get confidenceFilter() { return confidenceFilter; },
  get allKinds() { return allKinds; },
  get filteredFindings() { return filteredFindings; },
  get revealed() { return revealed; },

  setScanPath(value: string) { scanPath = value; },
  setPacksInput(value: string) { packsInput = value; },
  setMinConfidence(value: '' | 'low' | 'medium' | 'high') { minConfidence = value; },
  setKindFilter(value: string | null) { kindFilter = value; },
  setConfidenceFilter(value: '' | 'low' | 'medium' | 'high') { confidenceFilter = value; },

  async runScan() {
    loading = true;
    error = null;
    try {
      const path = scanPath.trim();
      if (!path) throw new Error('Enter a project path to scan.');
      const packs = packsInput.split(',').map((p) => p.trim()).filter(Boolean);
      currentReport = await invoke<ScanReport>('scan_run', {
        path,
        packs,
        min_confidence: minConfidence || null,
      });
      await this.refreshHistory();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  },

  async refreshHistory() {
    history = await invoke<ScanSummary[]>('scan_history_list');
  },

  async loadReport(id: string) {
    loading = true;
    error = null;
    try {
      currentReport = await invoke<ScanReport>('scan_report_get', { id });
      revealed = {};
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  },

  async storeReport(id: string) {
    await invoke<void>('scan_store', { report_id: id });
    await this.refreshHistory();
  },

  async reveal(reportId: string, findingIndex: number) {
    const key = `${reportId}:${findingIndex}`;
    if (revealed[key]) return revealed[key];
    const prefix = await invoke<string>('scan_reveal', { report_id: reportId, finding_index: findingIndex });
    revealed = { ...revealed, [key]: prefix };
    return prefix;
  },

  async setTriage(reportId: string, findingIndex: number, verdict: ScanVerdict) {
    await invoke<void>('scan_triage_set', { report_id: reportId, finding_index: findingIndex, verdict });
    if (currentReport && currentReport.id === reportId) {
      currentReport = {
        ...currentReport,
        findings: currentReport.findings.map((f, i) =>
          i === findingIndex ? { ...f, verdict } : f
        ),
      };
    }
  },
};
