# ADR-0015 — Unified runtime mediation stack for model, MCP, and process egress

- **Status:** Accepted — implementation pending
- **Date:** 2026-08-14
- **Deciders:** pealmeida

## Context

The evaluated artifact mediates Sovereign Vault MCP tools. It does not control
every path by which a CLI or IDE can place data in model context: text typed in
the prompt, content injected by another plugin, files read by native tools,
arbitrary shell output, and results returned by another MCP server may bypass
`sv-mcp`. Provider credentials are also commonly exposed to client processes
through environment variables or runtime files.

Closing those gaps requires more than another MCP tool. It requires a local
runtime boundary that can mediate model API traffic, MCP calls, and registered
processes while reusing the vault's identity, scope, consent, privacy, broker,
and tamper-evident audit capabilities.

This decision is future work. It does not change the capabilities or evidence
of the artifact evaluated in the thesis. In particular, it does not introduce
OS-level process isolation, prove complete interception, or verify retention by
an external AI provider.

## Decision

Add a Rust-native mediation stack composed of four crates and a set of client
adapters:

1. **`sv-runtime`** is the transport-independent policy plane. It authenticates
   principals, labels data, evaluates policy, manages opaque references, binds
   consent to an exact operation, and emits audit intent/outcome events.
2. **`sv-llm-gateway`** is the model data plane. It exposes OpenAI-compatible
   Responses and Chat Completions endpoints plus the Anthropic Messages API,
   sanitizes ingress and egress, and delegates authenticated provider calls to
   the broker without returning provider credentials to clients.
3. **`sv-mcp-router`** composes the existing Sovereign Vault tool server with
   registered external MCP servers. It filters tool arguments, resources,
   prompts, and results before they cross a trust boundary.
4. **`sv-process-broker`** runs only registered application profiles. It
   injects secrets at the latest possible point, constrains destinations and
   resources, filters output, and rejects arbitrary shell execution as a
   broker operation.
5. **Adapters** configure Codex, Claude Code, OpenCode, and generic MCP clients
   so their supported traffic enters the mediation stack. Hooks are
   defense-in-depth and coverage sensors; they are not the policy authority.

The implementation order is fixed as:

```text
sv-runtime -> OpenAI gateway -> MCP router -> process broker
-> Anthropic gateway support and client adapters
```

Arbitrary shell execution remains outside `sv-process-broker`. The broker
accepts only registered profiles with typed parameters and fixed executable
identity. Existing `.env.runtime` integration is classified as a weaker legacy
compatibility mode and will be replaced progressively by opaque references,
late binding, and brokered execution.

All first-party components on the security-critical path remain Rust and
inherit the workspace `unsafe_code = "forbid"` rule. JavaScript plugins and
provider shims, including AnyModel, may supply protocol observations,
compatibility fixtures, and provider-quirk test cases, but they do not receive
unredacted protected data or long-lived provider credentials in the target
architecture. This preserves ADR-0002's Rust-native trust boundary.

## Security invariants

The implementation must preserve the following invariants:

1. **Reference, do not reveal.** A secret classified as broker-only,
   process-only, or non-exportable is represented to the model by an opaque
   reference. No policy path may convert that reference into secret bytes for
   the model or client.
2. **Late binding.** Provider and application credentials are resolved only
   inside the trusted broker for an approved destination and operation.
3. **Deny overrides.** Any explicit deny, invalid policy, unknown content type,
   failed sanitizer, failed consent binding, or unavailable security component
   denies the affected egress. There is no silent direct-mode fallback.
4. **Elevation only.** Classification and runtime context may add redaction,
   consent, or denial; they may not weaken configured scopes or modes. This
   preserves ADR-0013's elevation-only rule.
5. **Consent is operation-bound.** Approval binds principal, resource,
   destination, action, payload digest, transformations, expiry, and nonce.
   Mutation of any bound field invalidates the approval.
6. **Every release is mediated.** Plaintext may cross a local trust boundary
   only after authentication, validation, scope enforcement, policy decision,
   required consent, transformation, and an audit intent record.
7. **Audit contains no protected value.** Audit records contain identifiers,
   policy versions, keyed digests, counts, decisions, timings, and outcomes,
   never prompts, secrets, raw tool output, or unredacted PII.
8. **Declared coverage, not presumed coverage.** An adapter reports which
   surfaces it controls. Unsupported or bypassed traffic is visible and must
   not be described as protected.

## Request order

For egress that may contain protected plaintext:

```
authenticate -> normalize -> validate -> label -> enforce scope
-> resolve references as policy metadata (not bytes)
-> scan/classify -> evaluate policy -> bind/obtain consent
-> transform -> create audit intent -> broker/route
-> sanitize result -> complete audit outcome -> release
```

Provider credentials are injected after request sanitization and immediately
before the outbound provider connection. Process secrets are injected after
profile validation and immediately before process start or brokered I/O.

## Compatibility boundary

The gateway initially targets:

- OpenAI Responses API: `POST /v1/responses`;
- OpenAI Chat Completions: `POST /v1/chat/completions`;
- Anthropic Messages: `POST /v1/messages`;
- streaming for all supported endpoints;
- function/tool calls and tool-result continuation.

Unsupported modalities, content blocks, or provider extensions are denied by
default until a parser, sanitizer, compatibility test, and policy rule exist.
Protocol translation must never silently drop security-relevant content.

## Consequences

### Positive

- One policy model covers prompt, model, MCP, and registered-process egress.
- Provider and application keys no longer need to be installed in each CLI or
  IDE environment.
- Opaque references allow a model to plan an action without possessing the
  credential used to execute it.
- External MCP results and model tool calls receive the same scope, consent,
  filtering, and audit semantics as vault tools.
- Compatibility is isolated in adapters while security decisions remain in a
  transport-independent crate.

### Negative

- The local gateway becomes a high-value, always-on component and expands the
  parsing, network, and compatibility attack surface.
- Complete mediation depends on client configuration. A client that calls a
  provider directly, runs an unregistered process, or connects to an external
  MCP server outside the router bypasses the stack.
- Supporting multiple evolving provider protocols creates ongoing conformance
  work and a risk of lossy translation.
- Plaintext still exists transiently in trusted process memory. This decision
  does not add OS memory isolation or verified zeroization of all dependency
  buffers.
- Sanitizing streaming output requires bounded buffering and may add latency.

### Mitigations

- Bind only to loopback or a local Unix socket/named pipe; require per-client
  authentication even on loopback.
- Use strict request, response, concurrency, redirect, and time limits.
- Keep provider transports in the existing SSRF-hardened broker boundary.
- Make protocol parsers bounded and fuzzed; retain raw-body logging as
  permanently disabled.
- Publish an adapter coverage matrix and a startup diagnostic that identifies
  direct-provider or unmediated MCP configuration.
- Ship components in phases and keep each new endpoint disabled until its
  conformance and adversarial suites pass.

## Alternatives considered

- **Use AnyModel directly as `sv-llm-gateway`.** Rejected for the trusted data
  plane. Its local Responses shim and provider quirks are useful reference
  material, but the current Node implementation has no inbound client
  authentication or Sovereign Vault policy path, reads provider keys from the
  environment, and has lossy protocol translation. Putting it in the trusted
  path would also reverse ADR-0002.
- **MCP-only protection.** Rejected because prompt text, native tools, direct
  model calls, and non-routed MCP servers remain bypasses.
- **Hooks-only protection.** Rejected because hook coverage and blocking
  semantics vary by client and plugins can execute before or outside hooks.
- **Materialize `.env.runtime` files.** Rejected as the target design because
  decrypted credentials persist on disk and become readable by the launched
  process and its children. A tightly scoped compatibility mode may remain,
  explicitly labeled weaker.
- **Transparent TLS interception.** Rejected as the default because it requires
  installing a local certificate authority, obscures application identity,
  breaks certificate pinning, and creates an unnecessarily broad interception
  surface.
- **OS-wide sandboxing and network enforcement.** Deferred. It can strengthen
  bypass resistance, but is platform-specific and must not be claimed by this
  logical mediation design.

## Evidence and thesis boundary

No thesis claim changes when this ADR is added. Each component remains
**planned** until code, regression tests, an updated threat model, and a
reproducible evaluation exist. Any later thesis update must distinguish:

- mediated requests from requests that bypass adapter configuration;
- detector performance from legal or semantic PII coverage;
- local gateway overhead from WAN and inference latency;
- logical mediation from OS/process isolation;
- provider-side behavior from locally observable behavior.

## Acceptance record

Accepted by the author on 2026-08-14 with the following explicit constraints:

1. the trusted data plane remains exclusively Rust;
2. AnyModel is used only as a source of protocol observations and synthetic
   fixtures, outside the trusted boundary;
3. implementation follows the ordered sequence recorded above;
4. the process broker never exposes arbitrary shell execution and supports
   only registered profiles;
5. `.env.runtime` is a weaker legacy mode to be retired progressively in favor
   of late binding and brokered secret use.

Acceptance selects the architecture; it does not assert that any component has
been implemented or evaluated.

## References

- [ADR-0002](0002-rust-native-mcp-server.md) — Rust-native security path.
- [ADR-0008](0008-per-agent-identity.md) — principal identity and scopes.
- [ADR-0009](0009-broker-and-transit-tools.md) — use without disclosure and
  outbound broker controls.
- [ADR-0010](0010-privacy-mediation-layer.md) — PII detection and masking.
- [ADR-0013](0013-sensitivity-classifier-adaptive-consent.md) — elevation-only
  adaptive consent and evidence limitations.
- [Runtime mediation implementation specification](../runtime/README.md).
