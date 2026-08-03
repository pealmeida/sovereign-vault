# Evidence Capture Plan — Real-Usage Telemetry for Thesis Chapter 4

**Purpose:** Turn *live operational use* of the Sovereign Vault into
supplementary thesis evidence that complements the controlled `thesis-eval`
harness ([EVALUATION.md](EVALUATION.md)). The harness proves
the artifact under synthetic, repeatable conditions; this plan captures
longitudinal, ecologically-valid data from the author's own daily workflow.

**Scope:** Single-user, single-machine, the author's development host. The
plan does **not** collect data from other users, does **not** phone home, and
does **not** record secret *content* — only operational metadata already
present in the MAC-authenticated chain (prev_mac/mac) audit log.

**Relation to thesis:** The captured evidence populates the qualitative
discussion in Chapter 4 (§4.3 *"Evidência Operacional"*) and provides
real-world grounding for the RQ answers in
[TRACEABILITY.md](TRACEABILITY.md).

---

## 1. Events to capture

Every event below is already written to the tamper-evident audit log
(`sv-audit`, append-only MAC-authenticated chain JSONL). The capture process
is **sampling + aggregation**, not new instrumentation.

### 1.1 Human approvals

| Audit field | What it records |
|---|---|
| `event.action` | `"read_file"`, `"write_file"`, `"list_files"`, `"delete_file"`, `"create_container"`, `"broker"` |
| `event.mode` | `"APPROVAL"` |
| `event.decision` | `"allowed"` or `"denied"` |
| `event.agent_id` | which agent requested |
| `event.timestamp` | ISO-8601 |

**Thesis value:** Counts approval/denial ratio per agent, per container, per
week. Demonstrates that the human-in-the-loop gate is exercised in practice,
not just in the harness. Feeds RQ1 (mediation) and RQ3 (isolation — a denied
request is a blocked lateral attempt).

### 1.2 OTP flows

| Audit field | What it records |
|---|---|
| `event.action` | `"read_file"`, `"write_file"`, `"list_files"`, `"delete_file"`, `"create_container"`, `"broker"` |
| `event.mode` | `"OTP"` |
| `event.decision` | `"allowed"` (correct OTP) or `"denied"` (wrong/missing OTP) |
| `event.detail` | human-readable string, e.g. `"approved via desktop modal (OTP)"` |

**Thesis value:** OTP is the strongest consent mode short of ZKP. Tracking
OTP success/failure rate shows whether the cross-channel property holds in
daily use. Feeds RQ1 (mediation strength) and the §3.6 module-4 claim
(*"Senha de Uso Único"*).

### 1.3 `SECRETS_SOURCE` fallback-to-env events

These are **client-side** events emitted by the Node/Python/shell loaders
(`clients/`). They are not in the vault audit log; they must be captured from
the loader's own output.

| Field | What it records |
|---|---|
| `source` | `"vault"`, `"env"`, or `"cache"` |
| `container` | which container was requested |
| `timestamp` | when the loader ran |
| `fallback_reason` | `"vault_unavailable"`, `"container_not_found"`, `"timeout"` |

**Thesis value:** The loaders implement a graceful-degradation contract:
when the vault is locked or unreachable, the agent falls back to `.env`.
Tracking how often this happens measures *operational availability* of the
local-first architecture. A low fallback rate strengthens the claim that the
vault is a practical daily driver, not a lab artifact. Feeds RQ2 (latency
and availability) and the §2.1 local-first narrative.

**Capture method:** Wrap the loader call in a shell function that logs
`SECRETS_SOURCE` and `SV_CONTAINER` to a dedicated JSONL file under
`target/evidence-capture/`.

### 1.4 Scoped-agent denials

| Audit field | What it records |
|---|---|
| `event.action` | the tool the agent tried to call (e.g. `"read_file"`, `"write_file"`) |
| `event.decision` | `"denied"` |
| `event.detail` | human-readable string, e.g. `"scope violation: agent X lacks read scope on container Y"` |
| `event.agent_id` | which agent was blocked |
| `event.container` | which container was out of scope |

**Thesis value:** Every scope denial is a *real* isolation event — an agent
attempted to reach data it was not granted. Counting these per agent per
week quantifies how often the scope mechanism prevents lateral access in
practice. This is the ecological counterpart to the adversarial battery's
10/10 block-rate ([EVALUATION.md §2](EVALUATION.md)). Feeds
RQ3 (OS-level isolation).

### 1.5 `ANONYMIZED` read events — instrumentation gap

> **⚠ Instrumentation gap.** The current `sv-audit` schema records
> `event.mode` (which can be `"ANONYMIZED"`) and a human-readable
> `event.detail` string, but it does **not** capture a structured count of
> PII redactions per operation. There is no `pii_redactions` field in
> `AuditEvent`, and `detail` is an unstructured string unsuitable for
> aggregation.

**What we can measure today:**

- Count of read operations on `ANONYMIZED` containers: filter on
  `event.action == "read_file"` and `event.mode == "ANONYMIZED"`.
- The `event.detail` string *may* contain redaction information (e.g.
  `"anonymized read: 3 PII spans redacted"`), but this is not guaranteed by
  the schema and cannot be reliably parsed.

**Recommendation (future work):** Add an optional `redaction_count: Option<usize>`
field to `sv-audit::AuditEvent`. The `sv-privacy` crate already knows how many
spans it redacts; plumbing that number into the audit event would close this
gap with minimal effort. Until then, the weekly capture table records
`ANONYMIZED` read *counts* only, not per-read redaction totals.

**Thesis value:** Counts how often the privacy filter fires in real use.
Complements the latency table in
[EVALUATION.md §1](EVALUATION.md) with ecological
frequency data. Feeds RQ1 (filter effectiveness). The redaction-count
limitation is documented as a known gap (§6).

---

## 2. Sampling the audit log without leaking secrets

The audit log (`sv-audit`) records **operational metadata only**: action,
container name (HMAC-redacted on disk), agent ID, decision, timestamp, mode,
and a human-readable `detail` string. The `detail` field for read/write
operations may contain the file path but **never the file content**. Secret
values are never written to the audit log.

**Sampling procedure (run weekly):**

```bash
# 1. The audit log lives at the vault root: ~/.local/share/com.sovereignvault.desktop/sovereign-vault/audit.jsonl
#    Each record is: {format_version, sequence, prev_mac, event, mac}
#    The event object is: {timestamp, action, decision, transport, container?,
#                          file_name?, mode?, byte_size?, detail?, error?, agent_id?}

# 2. Filter to the events of interest and aggregate:
jq -r '
  select(.event.action == "read_file" or .event.action == "write_file" or
         .event.action == "list_files" or .event.action == "delete_file" or
         .event.action == "create_container" or .event.action == "broker") |
  {
    ts: .event.timestamp,
    action: .event.action,
    container: .event.container,
    mode: .event.mode,
    decision: .event.decision,
    agent: .event.agent_id,
    detail: .event.detail
  }
' ~/.local/share/com.sovereignvault.desktop/sovereign-vault/audit.jsonl > target/evidence-capture/week-XX-audit-sample.jsonl
```

**What is NOT exported:** file contents, secret values, encryption keys,
recovery phrases, OTP codes, or any `detail` field that could contain
sensitive data beyond the whitelisted keys above. Container and file_name
values are HMAC-redacted on disk by `sv-audit` and are not reversible from
the sampled data.

**Chain-integrity check (optional, for the thesis appendix):**

```bash
# Verify the audit log chain has not been tampered before sampling.
# sv-audit exposes a VerifyReport API (verify_chain); if a CLI subcommand
# exists that wraps it, use:
sovereign-vault audit verify
# NOTE: the existence of a CLI subcommand for audit verification should be
# confirmed. The sv-audit crate provides AuditLog::verify_chain() → VerifyReport
# programmatically; a CLI wrapper may or may not be plumbed yet.
# If no CLI subcommand exists, note that the MAC-authenticated chain property
# is tested in CI and the sampled rows are a subset of a verified log.
```

---

## 3. Mapping events to thesis sections

### 3.1 Mapping to EVALUATION.md

| Evidence-capture event | EVALUATION.md section | Relationship |
|---|---|---|
| Human approvals (1.1) | §1 Latency decomposition | Ecological `T_hitl` — the harness uses auto-allow; real approvals measure *human* reaction time (seconds), which is the external parameter the harness flags as a caveat |
| OTP flows (1.2) | §1 Latency decomposition | Same as above; OTP adds code-entry time |
| `SECRETS_SOURCE` fallback (1.3) | §1 Latency decomposition | Measures *availability* — if the vault is unavailable, `T_total` is infinite for that operation; fallback rate is the complement of availability |
| Scoped-agent denials (1.4) | §2 Adversarial block-rate | Ecological counterpart to the 10/10 battery; real denials over weeks vs. synthetic probes in one run |
| `ANONYMIZED` reads (1.5) | §1 Latency decomposition | Ecological frequency of the PII filter path; complements the latency-per-byte table with real payload-size distributions |

### 3.2 Mapping to TRACEABILITY.md research questions

| Evidence-capture event | RQ | How it contributes |
|---|---|---|
| Human approvals + OTP (1.1, 1.2) | RQ1 (mediate and filter) | Shows the consent gate is exercised, not bypassed; approval/denial ratio quantifies human oversight |
| `ANONYMIZED` reads (1.5) | RQ1 (mediate and filter) | Shows the PII filter fires on real data; read counts per mode quantify filter load |
| `SECRETS_SOURCE` fallback (1.3) | RQ2 (latency impact) | Measures vault availability; a low fallback rate means the interception layer does not impair daily access |
| Scoped-agent denials (1.4) | RQ3 (isolation) | Real lateral-access blocks; complements the synthetic 10/10 with ecological evidence |
| All events | RQ3 (isolation) | Every event is MAC-authenticated-chain-recorded; the audit log itself is the tamper-evidence mechanism that proves isolation claims are not retroactively fabricated |

---

## 4. Weekly capture template

Capture once per week (e.g., Sunday evening). Fill one row in a running
Markdown table stored at `target/evidence-capture/README.md`.

### 4.1 Template table

| Week | Date range | Approvals | Denials (user) | OTP successes | OTP failures | Scope denials | `ANONYMIZED` reads | `SECRETS_SOURCE` vault | `SECRETS_SOURCE` env | `SECRETS_SOURCE` cache | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| W01 | YYYY-MM-DD–YYYY-MM-DD | | | | | | | | | | |
| W02 | | | | | | | | | | | |
| … | | | | | | | | | | | |

### 4.2 Column definitions

- **Approvals:** count of `event.decision == "allowed"` for `APPROVAL`-mode tool calls.
- **Denials (user):** count of `event.decision == "denied"` for `APPROVAL`-mode tool calls where `event.detail` indicates the human clicked "Deny" (e.g. contains `"rejected by user"`).
- **OTP successes:** count of `event.decision == "allowed"` for `OTP`-mode tool calls.
- **OTP failures:** count of `event.decision == "denied"` for `OTP`-mode tool calls (wrong or missing code).
- **Scope denials:** count of `event.decision == "denied"` where `event.detail` indicates a scope violation (e.g. contains `"scope violation"`).
- **`ANONYMIZED` reads:** count of `event.action == "read_file"` calls where `event.mode == "ANONYMIZED"`.
- **`SECRETS_SOURCE` vault/env/cache:** counts from the loader telemetry log (see §1.3).
- **Notes:** anything unusual — vault restarts, OS updates, new agents paired, config changes.

### 4.3 Automation script (run weekly)

```bash
#!/usr/bin/env bash
# scripts/capture-evidence-weekly.sh
# Run: bash scripts/capture-evidence-weekly.sh W03 2026-07-13 2026-07-19

WEEK="$1"
START="$2"
END="$3"
OUTDIR="target/evidence-capture"
mkdir -p "$OUTDIR"

AUDIT_LOG="${HOME}/.local/share/com.sovereignvault.desktop/sovereign-vault/audit.jsonl"
LOADER_LOG="${OUTDIR}/loader-telemetry.jsonl"

# --- Audit-log sample ---
if [ -f "$AUDIT_LOG" ]; then
  jq -r '
    select(.event.timestamp >= "'"$START"'" and .event.timestamp < "'"$END"'") |
    {
      ts: .event.timestamp,
      action: .event.action,
      container: .event.container,
      mode: .event.mode,
      decision: .event.decision,
      agent: .event.agent_id,
      detail: .event.detail
    }
  ' "$AUDIT_LOG" > "$OUTDIR/${WEEK}-audit-sample.jsonl"
fi

# --- Loader telemetry sample ---
if [ -f "$LOADER_LOG" ]; then
  jq -r '
    select(.timestamp >= "'"$START"'" and .timestamp < "'"$END"'")
  ' "$LOADER_LOG" > "$OUTDIR/${WEEK}-loader-sample.jsonl"
fi

# --- Print counts for manual table fill ---
echo "=== $WEEK ($START – $END) ==="
echo -n "Approvals:            "; jq -r 'select(.mode == "APPROVAL" and .decision == "allowed") | .decision' "$OUTDIR/${WEEK}-audit-sample.jsonl" | wc -l
echo -n "Denials (user):       "; jq -r 'select(.mode == "APPROVAL" and .decision == "denied") | .decision' "$OUTDIR/${WEEK}-audit-sample.jsonl" | wc -l
echo -n "OTP successes:        "; jq -r 'select(.mode == "OTP" and .decision == "allowed") | .decision' "$OUTDIR/${WEEK}-audit-sample.jsonl" | wc -l
echo -n "OTP failures:         "; jq -r 'select(.mode == "OTP" and .decision == "denied") | .decision' "$OUTDIR/${WEEK}-audit-sample.jsonl" | wc -l
echo -n "Scope denials:        "; jq -r 'select(.decision == "denied" and (.detail // "") | test("scope violation")) | .decision' "$OUTDIR/${WEEK}-audit-sample.jsonl" | wc -l
echo -n "ANONYMIZED reads:     "; jq -r 'select(.action == "read_file" and .mode == "ANONYMIZED") | .action' "$OUTDIR/${WEEK}-audit-sample.jsonl" | wc -l
echo -n "Loader vault:         "; jq -r 'select(.source == "vault") | .source' "$OUTDIR/${WEEK}-loader-sample.jsonl" | wc -l
echo -n "Loader env:           "; jq -r 'select(.source == "env") | .source' "$OUTDIR/${WEEK}-loader-sample.jsonl" | wc -l
echo -n "Loader cache:         "; jq -r 'select(.source == "cache") | .source' "$OUTDIR/${WEEK}-loader-sample.jsonl" | wc -l
```

---

## 5. How this evidence appears in the thesis

| Thesis location | Evidence injected |
|---|---|
| §4.1 (latency results) | `SECRETS_SOURCE` availability rate alongside the harness's µs table; ecological `T_hitl` distribution from approval/OTP timestamps |
| §4.2 (adversarial results) | Scope-denial count over N weeks as ecological confirmation of the 10/10 block-rate |
| §4.3 (operational evidence) | Full weekly table as a longitudinal appendix; approval/denial ratio; PII-filter frequency |
| §4.4 (discussion) | Triangulation: harness numbers + ecological numbers + threat-model coverage |
| Appendix B | Raw weekly capture tables and the sampling script |

---

## 6. Limitations (state these in the thesis)

- **Single-user, single-machine.** The evidence is from the author's own
  workflow; it is not a multi-user study. Generalisability is limited.
- **Observer effect.** Knowing the audit log exists may change behaviour
  (e.g., fewer denied requests because the author is also the vault operator).
- **Loader telemetry is best-effort.** The `SECRETS_SOURCE` wrapper must be
  manually installed in each shell/profile; gaps are possible.
- **Audit log sampling is post-hoc.** The weekly script samples a
  MAC-authenticated chain log, but the sampling itself is not real-time. The
  chain integrity check should be run before each sample.
- **No structured redaction counts.** The current `sv-audit` schema does not
  include a `redaction_count` field. Only the count of `ANONYMIZED`-mode
  reads can be measured; per-read PII-redaction totals are not available
  without a schema change (see §1.5 recommendation).
- **No content analysis.** PII redaction counts are not recorded, and the
  *types* of PII (CPF vs. email vs. phone) are not disaggregated in the
  current audit detail; this could be added to `sv-audit` if needed.
