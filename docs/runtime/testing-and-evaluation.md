# Runtime Testing and Evaluation Plan

## 1. Evidence boundary

This plan is prospective. Passing unit tests is not evidence that every CLI/IDE
path is intercepted, every PII form is detected, provider retention is
controlled, or OS/process isolation exists. Capability claims require the exact
implemented surface and measured protocol below.

## 2. Test layers

### Unit

- strict policy parse/validation/composition;
- reference lifecycle and concurrent use;
- canonical operation/consent digests;
- content normalization and transformation;
- protocol mappings and error mappings;
- profile/path/destination validation;
- audit event construction with forbidden-field assertions.

### Property and fuzz

- deny remains deny under added request fields;
- adding classification cannot weaken exposure/consent;
- canonicalization is deterministic and mutation changes digest;
- parser never panics and respects allocation/depth/count limits;
- random chunking yields the same sanitized text as whole-input scanning within
  declared detector semantics;
- reference tokens do not collide in generated samples;
- MCP/HTTP/SSE malformed frames terminate safely;
- path/URL normalization cannot escape registered roots/destinations.

### Integration

- real `sv-runtime` + in-memory/test vault + authenticated audit;
- loopback gateway + deterministic provider fixture;
- router + malicious MCP fixture servers;
- broker + purpose-built test executables;
- desktop/terminal consent controllers;
- lock/revoke/reload/cancel races.

### Client conformance

For each supported Codex, Claude Code, and OpenCode version:

- clean config detection and idempotent apply/remove;
- non-streaming and streaming model calls;
- tool call/result continuation;
- MCP discovery/call/result;
- hook action/provenance where supported;
- lock and revoked-client behavior;
- coverage/bypass diagnostic.

## 3. No-real-provider test rule

Automated tests clear all known provider-key variables and use fixture-only
route configuration. A test process fails at startup if ambient provider keys
are present unless an explicit, separately named manual-live profile is chosen.
Fixture hosts bind locally and network-deny tests verify no external connection.

This rule prevents the observed AnyModel behavior where a nominal missing-key
test inherited a real credential and obtained an upstream `200`.

## 4. Canary strategy

Generate unique synthetic canaries per test for:

- provider key;
- process secret;
- CPF/CNPJ/card/email/phone categories;
- reference token and internal resource ID;
- prompt, tool result, MCP resource, process stdout/stderr.

After each test, scan all observable surfaces:

- fixture provider requests;
- client responses;
- MCP/process fixture input;
- stdout/stderr;
- application logs and traces;
- audit files;
- generated config/state files;
- process command lines captured by the fixture OS harness.

Expected occurrences are specified per surface. Unexpected canary occurrence is
a hard failure.

## 5. Adversarial battery

### Gateway

- PII in every supported message/content field;
- PII split across JSON strings, Unicode boundaries, and SSE chunks;
- alternate/unknown fields and duplicate JSON keys;
- tool descriptions/schemas containing injection and canaries;
- tool arguments delivered incrementally;
- encoded secret echoes in supported bounded transformations;
- oversized/nested/decompression/request-smuggling inputs;
- upstream redirects, DNS rebinding, private IP, slowloris, malformed SSE,
  missing terminal event, and hostile error body;
- client disconnect before/after partial release.

### References and consent

- guessed, expired, revoked, cross-session, cross-principal, and
  cross-destination references;
- replay and concurrent double use;
- mutate model, tool schema, profile, executable, args, body, destination,
  transformation, or policy after approval;
- delayed approval after expiry;
- audit-intent failure and outcome-audit failure.

### MCP router

- unregistered server/tool/resource/prompt;
- tool namespace collision and Unicode confusable names;
- schema change after approval;
- malicious description/instruction;
- malformed/oversized content blocks and embedded resources;
- external server attempting environment/credential discovery;
- external result containing PII/secret/prompt injection;
- direct MCP configuration bypass detected by adapter doctor.

### Process broker

- arbitrary shell/interpreter injection;
- path traversal, symlink/junction/reparse escape;
- executable replacement between approval and start;
- child spawn, orphan, timeout, and termination races;
- argv/environment/stdin/temp-file leakage checks;
- stdout/stderr secret echo split across chunks;
- ANSI/control sequence injection and binary output;
- unapproved network destination when brokered transport is used.

### Adapters

- direct provider base URL/key left active;
- another plugin overwriting gateway config;
- unsupported client version/schema;
- hook unavailable or non-blocking;
- native file/shell tool bypass;
- another MCP server configured directly.

## 6. Functional acceptance matrix

| Scenario | Expected |
|---|---|
| clean public prompt | reaches fixture unchanged where policy allows |
| prompt with supported PII | fixture sees configured redaction/pseudonym only |
| broker-only ref in prompt | model sees safe capability, never value |
| allowed tool call | complete args evaluated, then released/executed through owner |
| denied tool call | safe typed error, no execution |
| external MCP PII result | filtered before client/model |
| registered process secret | injected by declared method, not argv/log/audit |
| output echoes secret | redacted/denied and count audited |
| sanitizer/policy/audit unavailable | no release |
| unconfigured direct client path | adapter status reports unmediated |

## 7. Performance measurement

Extend the existing latency decomposition without replacing its historical
evidence. Proposed runtime measurements:

```text
T_runtime = T_auth + T_parse + T_scope + T_scan + T_policy
          + I_consent(T_consent) + T_transform + T_audit_intent
          + T_route + T_egress_filter + T_audit_outcome
```

Measure separately:

- gateway non-streaming overhead by payload size and protocol;
- time-to-first-safe-byte and total streaming overhead;
- chunk-boundary buffer cost;
- MCP discovery/call/result filtering;
- process start/injection/output filtering;
- reference lookup/consent canonicalization/audit;
- concurrency and memory high-water mark.

WAN and inference time remain external terms and are reported separately.
Human reaction time is not simulated as gateway latency.

Reportable runs follow the repository evidence rule:

- release build;
- at least three independent sessions;
- 95% bootstrap confidence intervals;
- predeclared warmup/discard rule;
- OS/kernel, CPU, RAM, storage, rustc, profile, command, power mode, and date;
- raw versioned output with SHA-256 hashes.

## 8. Privacy evaluation

Report detector precision/recall per category and final policy outcome
precision/recall where classification is used. Synthetic data limitations and
category prevalence are explicit. A redaction pass rate is not LGPD compliance,
semantic sensitivity detection, or proof of non-identifiability.

Streaming evaluation includes cross-chunk cases and measures whether buffering
changes detector outcomes. Binary/unsupported content is reported as denied,
not counted as correctly sanitized.

## 9. Coverage metric

For each client/version, publish a surface matrix with one of:

- `mediated-and-blocking`;
- `mediated-observation-only`;
- `detected-bypass`;
- `unsupported`;
- `not-tested`.

Do not collapse these into a single “100% protected” percentage. An aggregate
may report coverage of a pre-specified test battery only, with the battery and
denominator visible.

## 10. Release gate

Release requires:

- all workspace tests and targeted suites pass;
- fuzz budget completed with no unresolved crash/limit bypass;
- zero unexpected canary occurrence;
- no critical/high unresolved security findings;
- client coverage matrices published;
- performance protocol satisfied;
- threat model and operational docs updated;
- independent methodology/security/privacy reviews recorded;
- negative results and unsupported surfaces retained, not tuned away.

