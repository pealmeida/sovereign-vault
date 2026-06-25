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

**Sample results** (release build, 1000 reads/cell, microseconds, mean; p95 of total in parentheses):

| Mode | Bytes | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | **T_total** |
|---|---|---|---|---|---|---|
| direct | 128 | 39.5 | 0.07 | 0.71 | 33.3 | **73.6** (p95 116.5) |
| direct | 16384 | 49.3 | 0.08 | 0.74 | 66.9 | **117.1** (p95 177.8) |
| approval | 16384 | 52.7 | 0.08 | 0.80 | 70.4 | **123.9** (p95 204.6) |
| anon | 128 | 39.2 | 6.65 | 0.74 | 32.2 | **78.8** (p95 131.4) |
| anon | 1024 | 44.5 | 29.4 | 0.78 | 37.3 | **112.0** (p95 196.3) |
| anon | 16384 | 76.4 | 432.9 | 1.22 | 83.6 | **594.1** (p95 879.2) |

**Reading it.** A read through the full gateway costs ≈74 µs for a small file,
split between local retrieval (`T_vault` ≈33 µs) and request validation/scope
(`T_filter` validate ≈40 µs); `T_vault` grows with payload size. The PII filter
is effectively free for non-anonymised modes (~0.07 µs — just the mode check)
but becomes the dominant added cost for `ANONYMIZED` reads, scaling with content
length (≈6.6 µs at 128 B → ≈433 µs at 16 KB). This is the central §3.9.1
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

---

## 2. Adversarial / prompt-injection block-rate (§3.9.2)

A black-box battery models an external model that has been prompt-injected into
trying to exfiltrate local data. It runs over the **authenticated WebSocket**
transport, so it exercises the *real* `enforce_scopes`, path validation, and a
headless mirror of the desktop consent policy — not mocks. A least-privilege
agent (read-only on `public`) and the unscoped Default agent issue the probes.
"Blocked" = the tool call returns an error.

**Result:** **8 / 8 attacks blocked (100 %)**, 2 / 2 legitimate controls allowed
(100 % availability), every event recorded to the tamper-evident audit log.

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
| C1 | control | read own `public` file (in scope) | — | allowed ✓ |
| C2 | control | list files in `public` (in scope) | — | allowed ✓ |

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
