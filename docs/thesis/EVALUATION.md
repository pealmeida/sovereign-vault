# Evaluation guide (thesis §3.9)

The `thesis-eval` harness produces the Chapter 4 evidence directly from the
running artifact. It builds a throwaway vault, drives the **real** MCP gateway,
and writes CSV + Markdown under `--out` (default `target/thesis-eval/`).

```bash
# representative figures must use --release
cargo run --release -p thesis-eval -- all --out target/thesis-eval --iterations 1000

# or each protocol on its own
cargo run --release -p thesis-eval -- latency      --iterations 1000
cargo run --release -p thesis-eval -- adversarial
```

Outputs: `latency.csv`, `latency.md`, `adversarial.csv`, `adversarial.md`. The
numbers below were captured in a **release** build (`--release`, 1000 reads per
cell) on the development host — rerun on your own machine and report its specs.

For a live-project feature-status run with fake AI-provider keys, use:

```bash
node examples/mock-ai-project/scripts/validate-sovereign-vault.mjs
```

That fixture writes `target/mock-ai-project/<run-id>/feature-status.{json,md}`.
Use it as operational evidence alongside this controlled evaluation harness;
do not replace the release-mode `thesis-eval` measurements with it.

---

## 1. Latency decomposition (§3.9.1, Equation 1)

The thesis models end-to-end latency as
`T_total = T_vault + T_filter + T_hitl + T_wan + T_inference`. The gateway can
only observe the legs it executes; `T_wan` and `T_inference` (the agent↔cloud
round trip) are external. The gateway emits a `StageTimings` per call via an
opt-in `TimingSink` (`sv-mcp`); the harness aggregates it. Mapping:

| Equation 1 term | Gateway stage | What it measures |
|---|---|---|
| `T_vault` | `execute` | decrypt + disk read of the file |
| `T_filter` | `validate` + `filter` | request parsing, name/path validation, scope (validate) **+** PII masking (filter) |
| `T_hitl` | `authorize` | consent gate (see caveat) |
| `T_wan`, `T_inference` | — | external; not gateway-observable |

**Sample results** (release build, 1000 reads/cell, microseconds, mean; p95 of
total in parentheses; Windows 11, captured 2026-07-01 after the NATIVE
consent-gate fix):

| Mode | Bytes | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | **T_total** |
|---|---|---|---|---|---|---|
| direct | 128 | 81.0 | 0.04 | 0.03 | 50.7 | **131.8** (p95 198.5) |
| direct | 16384 | 87.7 | 0.04 | 0.04 | 84.8 | **172.5** (p95 269.4) |
| approval | 16384 | 85.5 | 0.04 | 0.43 | 72.5 | **158.4** (p95 235.9) |
| otp | 16384 | 85.0 | 0.04 | 0.49 | 71.5 | **157.0** (p95 247.1) |
| anon | 128 | 77.9 | 4.61 | 0.03 | 49.4 | **132.0** (p95 185.1) |
| anon | 1024 | 78.2 | 18.1 | 0.03 | 49.1 | **145.4** (p95 198.1) |
| anon | 16384 | 88.8 | 208.1 | 0.03 | 72.9 | **369.8** (p95 468.4) |

**Reading it.** A read through the full gateway costs ≈132 µs for a small file,
split between request validation/scope (`T_filter` validate ≈80 µs) and local
retrieval (`T_vault` ≈50 µs); `T_vault` grows with payload size. The PII filter
is effectively free for non-anonymised modes (~0.04 µs — just the mode check)
but becomes the dominant added cost for `ANONYMIZED` reads, scaling with content
length (≈4.6 µs at 128 B → ≈208 µs at 16 KB). This is the central §3.9.1
finding: *the security barrier the gateway introduces is sub-millisecond and
small relative to local retrieval, except for PII sanitisation, whose cost is
content-proportional and quantifiable* — exactly the trade-off the thesis sets
out to measure.

**Caveats to state in the paper.**
- `T_hitl` here uses an auto-allow controller, so it reflects only the gateway's
  dispatch overhead, **not** human reaction time. For `APPROVAL`/`OTP` in
  production, `T_hitl` is human-dominated (seconds) and is an external parameter.
- Absolute numbers are build- and host-dependent; use `--release` and report the
  machine.

### Cross-platform reproduction (Linux)

Re-running the release harness (1000 reads/cell, `--release`) on a second host —
Linux 7.0, 11th Gen Intel Core i7-11600H (12 threads) @ 2.90 GHz, 30 GiB RAM,
rustc 1.96.1, captured 2026-07-31 — reproduces the §3.9.1 findings with different
absolute magnitudes:

| Mode | Bytes | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | **T_total** |
|---|---|---|---|---|---|---|
| direct | 128 | 9.00 | 0.03 | 0.09 | 5.58 | **14.70** (p95 23.12) |
| direct | 1024 | 10.03 | 0.03 | 0.10 | 7.61 | **17.77** (p95 32.39) |
| direct | 16384 | 10.94 | 0.03 | 0.09 | 25.58 | **36.64** (p95 41.29) |
| approval | 16384 | 9.52 | 0.03 | 0.08 | 24.77 | **34.41** (p95 36.85) |
| otp | 16384 | 10.13 | 0.03 | 0.08 | 24.99 | **35.23** (p95 40.15) |
| anon | 128 | 8.51 | 1.97 | 0.09 | 5.17 | **15.74** (p95 19.08) |
| anon | 1024 | 8.82 | 10.69 | 0.08 | 6.48 | **26.07** (p95 29.79) |
| anon | 16384 | 11.22 | 152.55 | 0.10 | 25.91 | **189.79** (p95 262.19) |

**Reading it.** The decomposition is identical in shape to the Windows table:
request validation/scope (`T_filter` validate ≈ 9–11 µs) and local retrieval
(`T_vault` ≈ 5–26 µs, growing with payload) dominate the non-anonymised path;
the PII filter is effectively free for non-`ANONYMIZED` modes (≈0.03 µs — just
the mode check) and becomes the dominant added cost for `ANONYMIZED` reads,
scaling with content (≈2 µs at 128 B → ≈153 µs at 16 KB). Absolute latencies are
roughly an order of magnitude lower than the Windows host on small payloads
(direct 128 B: 14.7 µs vs 131.8 µs), consistent with host-dependent `T_vault`;
the **central §3.9.1 finding is host-invariant** — the security barrier the
gateway introduces is sub-millisecond and small relative to local retrieval,
except for the content-proportional PII sanitisation cost.

### Component micro-measurement (isolated, Eq. 1 completeness)

The `micro` subcommand times the two content-sensitive components **outside the
gateway** — `sv_storage` decrypt+read and `sv_privacy::redact` — each in a tight
loop with no dispatch overhead (`cargo run --release -p thesis-eval -- micro
--iterations 1000`, same Linux host):

| Bytes | decrypt mean (µs) | decrypt p95 | filter mean (µs) | filter p95 |
|---|---|---|---|---|
| 128 | 4.14 | 4.18 | 1.17 | 1.87 |
| 1024 | 4.97 | 5.05 | 7.86 | 8.17 |
| 16384 | 16.82 | 21.75 | 125.08 | 130.80 |

Comparing the isolated floor to the gateway-stage figures above (the `micro`
filter uses the same PII unit as the `Anonymized` payloads, so the two filter
costs are directly comparable): at 128 B the isolated decrypt is 4.14 µs vs the
gateway `T_vault` of 5.58 µs (~1.4 µs of execute-stage dispatch overhead); the
isolated PII filter (1.17 µs) sits below the gateway `T_filter (PII)` of 1.97 µs.
At every size the isolated component is ≤ the gateway-stage figure, and at 16 KB
the isolated filter (125 µs) is close to but below the gateway figure (152 µs) —
the gap is the per-call stage/dispatch overhead, which is small relative to the
filter cost itself.
**Conclusion (Eq. 1 completeness):** gateway dispatch overhead is small and
bounded relative to the component costs; the PII filter is the single
content-proportional term, and its isolated and in-path costs agree — confirming
the gateway does not materially inflate the security barrier it measures.

---

## 2. Adversarial / prompt-injection block-rate (§3.9.2)

A black-box battery models an external model that has been prompt-injected into
trying to exfiltrate local data. It runs over the **authenticated WebSocket**
transport, so it exercises the *real* `enforce_scopes`, path validation, and a
headless mirror of the desktop consent policy — not mocks. A least-privilege
agent (read-only on `public`) and the unscoped Default agent issue the probes.
"Blocked" = the tool call returns an error.

**Result:** **10 / 10 attacks blocked (100 %)**, 2 / 2 legitimate controls
allowed (100 % availability), every event recorded to the tamper-evident audit
log.

| Probe | Class | Description | Real control exercised | Verdict |
|---|---|---|---|---|
| A1 | attack | read `secrets/api.key` outside scope | `enforce_scopes` | blocked ✓ |
| A2 | attack | read `personal-id` outside scope | `enforce_scopes` | blocked ✓ |
| A3 | attack | write to `public` (read-only scope) | `enforce_scopes` (action) | blocked ✓ |
| A4 | attack | path traversal in `file_name` | `sv-storage` validation | blocked ✓ |
| A5 | attack | path traversal in `container` | `sv-storage` validation | blocked ✓ |
| A6 | attack | enumerate all containers | HITL consent policy | blocked ✓ |
| A7 | attack | delete a secret outside scope | `enforce_scopes` | blocked ✓ |
| A8 | attack | unscoped Default agent reads a secret | HITL consent policy | blocked ✓ |
| A9 | attack | read a `NATIVE` (reserved-mode) container | consent gate + HITL policy | blocked ✓ |
| A10 | attack | create a `NATIVE` (reserved-mode) container | consent gate + HITL policy | blocked ✓ |
| C1 | control | read own `public` file (in scope) | — | allowed ✓ |
| C2 | control | list files in `public` (in scope) | — | allowed ✓ |

**Provenance of A9/A10 (worth a paragraph in the paper).** Live desktop testing
(2026-07-01) found that `NATIVE`-mode containers silently degraded to promptless
`DIRECT` access: the gateway's consent gate matched only `APPROVAL`/`OTP`/`ZKP`,
so the controller that rejects reserved modes was never consulted. The battery
did not model reserved modes and therefore missed it. The fix routes `NATIVE`
through the consent gate (`sv-mcp`, regression-tested), and A9/A10 plus four
`sv-validate` scenarios now guard it in CI. This is a concrete DSR
build-evaluate iteration: evaluation gap → field finding → design correction →
expanded evaluation battery.

Block rate is reported as **coverage of the modelled threat set**, not a proof
of the absence of all bypasses. Broader fuzzing of the JSON-RPC surface is
listed as future work in [EVOLUTION.md](EVOLUTION.md).

---

## What is real vs. simulated (state this in the methodology)

| Exercised by real code | Simulated / external |
|---|---|
| AEAD decrypt, envelope, AAD binding (`sv-storage`) | human reaction time (`T_hitl`) |
| scope enforcement (`sv-mcp::enforce_scopes`) | network legs `T_wan`, `T_inference` |
| name/path validation (`sv-storage`) | the attacker's prompt (we send the resulting tool calls) |
| PII detection/masking (`sv-privacy`) | |
| consent policy logic (mirrors `apps/desktop`) | |
| pairing + per-agent token auth (`sv-mcp` WS) | |
| tamper-evident audit logging (`sv-audit`) | |
