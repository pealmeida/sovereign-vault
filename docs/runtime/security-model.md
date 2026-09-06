# Runtime Mediation Security Model

This document is a proposed delta to the current
[threat model](../threat-model.md). It becomes part of the product threat model
only after the corresponding code ships.

## 1. Assets

- Vault secrets, transit keys, signing keys, provider keys, and application
  credentials.
- PII and other protected text in prompts, files, tool results, MCP resources,
  process output, and model responses.
- Policy, profile, route, reference, identity, and consent state.
- Integrity and availability of the mediation and audit path.
- Metadata that can reveal resource names, providers, destinations, timing, or
  usage patterns.

## 2. Adversaries

1. A prompt-injected or malicious model that requests unauthorized tools,
   references, files, destinations, or commands.
2. A compromised CLI/IDE/plugin that sends data through unexpected fields,
   bypasses adapters, replays consent, or connects directly to a provider.
3. A malicious external MCP server that returns prompt injection, secret-like
   data, oversized payloads, malformed content, or changed tool schemas.
4. A malicious or compromised registered application that echoes secrets,
   spawns children, reads inherited state, or exfiltrates over the network.
5. Another local process attempting to use the loopback gateway or consume
   provider quota.
6. An attacker with read/write access to disk while the vault is locked.

A fully compromised same-user OS session remains outside the current product
boundary. Such an attacker may inspect process memory, environment blocks,
debug interfaces, pipes, or keystrokes. No runtime document may imply otherwise.

## 3. Mandatory invariants

### I1 — authenticated local entry

Every gateway, router, and broker request has an authenticated principal.
Loopback address alone is not authentication. Tokens are per client, stored
hashed, scoped, expiring where practical, and never reused as provider keys.

### I2 — least privilege before content access

Scope and registration checks happen before reading a vault item, invoking an
external MCP server, or starting a process. Content-dependent classification
may require a trusted local read after scope enforcement and before consent, as
specified by ADR-0013.

### I3 — no secret-bearing model representation

Broker-only, process-only, transit-only, signing-only, and non-exportable key
classes are represented by opaque references and safe metadata. Descriptions
must not encode the secret.

### I4 — exact destination binding

A credential is usable only for its registered provider/API host, MCP
server/tool, or process profile. Redirects, DNS resolution, scheme, method,
path, and resolved address are checked using ADR-0009 broker controls.

### I5 — transformation before release

No content is streamed outward until its release unit can be safely classified
and transformed. For text streams the sanitizer retains enough boundary data
to detect a sensitive token split across chunks.

### I6 — consent cannot be replayed or broadened

Consent grants bind a canonical operation digest, principal, destination,
policy version, transformations, expiry, and nonce. Parameter, body, tool
schema, executable, or destination changes invalidate the grant.

### I7 — audit before release

An authenticated intent record is durable before egress or irreversible
execution. Outcome events link to the intent. Audit failure is not converted to
success.

### I8 — no plaintext observability

Logs, traces, crash reports, metrics, errors, and health endpoints contain no
raw request body, response body, secret, prompt, tool result, or PII. Debug mode
does not relax this invariant.

## 4. Data classes and permitted representations

| Class | Model/API | MCP result | Registered process | User-local output |
|---|---|---|---|---|
| public | allowed by route policy | allowed | allowed | allowed |
| PII-redactable | redacted/pseudonymized | filtered | filtered input/output | reversible only if explicitly allowed |
| revealable secret | exceptional explicit release + consent | exceptional | allowed only by profile | explicit reveal UX only |
| broker-only secret | opaque reference only | opaque reference only | injected by broker | never displayed by default |
| non-exportable key | operation reference only | operation result only | cryptographic operation only | public key/result only |
| unknown/binary | deny unless an explicit typed parser policy exists | deny/omit block | deny injection; bounded output handling | local user may access outside model path |

## 5. Exposure-route coverage

| Route | Primary control | Residual limit |
|---|---|---|
| PII typed in prompt | LLM gateway ingress sanitizer | bypass if client calls provider directly |
| plugin content before model | gateway sanitizer | origin may be indistinguishable without hook metadata |
| native file-read result | gateway on next model request; adapter hook for action | file may already be visible to local client/plugin |
| arbitrary shell command | adapter hook blocks or redirects registered actions | shell outside broker is not sandboxed by this architecture |
| other MCP server result | MCP router result filter, then gateway | bypass if client connects directly to that server |

Complete protection therefore requires both routing and configuration
attestation. Startup diagnostics should detect known direct provider keys/base
URLs and unregistered MCP entries, but diagnostics are not OS enforcement.

## 6. Gateway threats and controls

- **Request smuggling/ambiguity:** one HTTP parser, strict content length,
  reject conflicting framing and invalid encodings.
- **Oversized bodies/decompression bombs:** compressed input disabled initially;
  hard limits before allocation; per-content limits after decoding.
- **Parser differentials:** canonical internal model and conformance fixtures;
  never sanitize one representation and forward a different raw body.
- **Streaming boundary evasion:** bounded carry-over window, Unicode-safe
  segmentation, tool-argument accumulation before authorization.
- **Credential theft:** clients receive local credentials only; provider auth is
  added inside broker transport; outbound errors strip headers.
- **Quota abuse:** per-principal rate, concurrency, token, and byte budgets.
- **Cross-session reference use:** references are random, scoped, expiring, and
  audience-bound.

## 7. MCP threats and controls

- External servers are registered by stable ID and exact transport.
- Tool schemas are hashed; a schema change disables the tool pending review.
- `tools/list`, prompts, resources, and completion metadata are untrusted input.
- Tool descriptions are length-limited and never treated as policy.
- Arguments pass through structural validation and policy before forwarding.
- Every returned text/resource block is labeled and sanitized.
- Nested URLs, resource links, embedded files, and images are denied until a
  typed policy exists.
- External servers never receive vault client tokens or unrelated environment
  variables.

## 8. Process threats and controls

- No `shell=true`, `cmd /c`, `sh -c`, PowerShell script string, or arbitrary
  executable path in a broker profile.
- Executable path, optional publisher/hash, arguments, working directory,
  environment allowlist, network destinations, child-process policy, and
  output limits are registered.
- The model selects a profile and typed parameters, not a command string.
- Environment injection is a compatibility fallback because the process and
  its children can read it. Pipe/FD or brokered HTTP injection is preferred.
- Temporary secret files are disabled by default and never described as equal
  to no-disk injection.
- Output is filtered for direct secret echo, known references, PII, and size.

## 9. Audit and privacy

Audit events use keyed digests for sensitive identifiers. Counts and coarse
labels can still reveal metadata and remain authenticated but not necessarily
encrypted. The audit policy must define retention, rotation, export, and which
operator views can resolve labels.

No event records detector findings, exact score, raw prompt, full destination
URL query, command output, secret name in plaintext, or HTTP headers. A separate
local diagnostic capture can exist only as an explicit short-lived user action,
encrypted under the vault and excluded from normal operation and evaluation.

## 10. Security acceptance gates

The stack cannot be called a security boundary until tests demonstrate:

- authentication and scope denial on every public endpoint;
- fail-closed sanitizer and policy failures;
- consent replay/mutation rejection;
- no secret bytes in model/provider fixtures, logs, audit, errors, or process
  lists;
- blocked direct reference resolution from model/MCP paths;
- SSRF/redirect/DNS rebinding controls on provider and broker transports;
- bounded parsing, streaming, concurrency, and output;
- adapter coverage and bypass warnings for every supported client.

