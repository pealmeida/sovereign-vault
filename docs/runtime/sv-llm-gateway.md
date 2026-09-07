# `sv-llm-gateway` Specification

## 1. Responsibility

`sv-llm-gateway` is a local authenticated API gateway for model traffic. It:

- accepts supported OpenAI and Anthropic request formats;
- converts them to the canonical runtime content model;
- sanitizes everything that can reach a model;
- obtains a policy plan and durable audit intent from `sv-runtime`;
- asks the broker to call the registered provider route with late-bound auth;
- sanitizes model text, tool calls, and errors before returning them;
- preserves streaming behavior within declared compatibility limits.

It does not expose vault tools itself, execute model-generated commands, or
store conversation history.

## 2. Listener and authentication

Initial listener:

- `127.0.0.1` only, configurable port chosen or reserved by the runtime;
- optional Windows named pipe / Unix domain socket after client compatibility
  is proven;
- no remote bind in version 1;
- HTTP/1.1 initially; no cleartext non-loopback traffic;
- per-client bearer credential issued by Sovereign Vault and bound to an agent
  identity/adapter;
- request ID generated locally; client IDs are treated as hints.

`Authorization` from the client authenticates to Sovereign Vault. It is removed
and never forwarded. Provider authentication is added by the broker.

## 3. Supported API surface

### OpenAI-compatible

| Endpoint | Initial status | Notes |
|---|---|---|
| `POST /v1/responses` | required | text, function tools, streaming/non-streaming |
| `POST /v1/chat/completions` | required | text, function tools, streaming/non-streaming |
| `GET /v1/models` | required | returns configured aliases/safe metadata only |
| `GET /health` | required | no vault/provider secrets or detailed configuration |
| file/upload/batch/vector endpoints | unsupported | return typed error |

### Anthropic-compatible

| Endpoint | Initial status | Notes |
|---|---|---|
| `POST /v1/messages` | required | text, tool use/results, streaming/non-streaming |
| `POST /v1/messages/count_tokens` | optional | local conservative count or routed count without logging |
| Files, Batches, admin APIs | unsupported | typed error |

The exact accepted field matrix is versioned in conformance fixtures. Passing a
top-level endpoint does not imply support for every field or content block.

## 4. Model routes and aliases

Clients request a local alias such as `sv/zai-glm-5.2` or `sv/claude-review`.
The control plane maps the alias to a registered provider route and upstream
model. The public models response must not reveal credential references,
internal vault paths, or unregistered models.

Routing inputs allowed from clients:

- declared model alias;
- supported inference parameters constrained by route policy;
- optional adapter metadata authenticated or attested by configuration.

Clients cannot supply arbitrary upstream base URLs, authorization headers,
proxy settings, TLS settings, or provider credential names.

## 5. Ingress sanitization

### 5.1 What is inspected

OpenAI:

- `instructions`;
- every message/input text part;
- function/tool descriptions and JSON schemas;
- prior tool-call arguments and tool-result output;
- metadata fields only if explicitly forwardable;
- model and generation parameters for route policy.

Anthropic:

- `system` blocks;
- every `messages[].content` text block;
- `tool_use.input` and `tool_result.content`;
- tool descriptions and input schemas;
- metadata only when allowlisted.

Schemas and tool descriptions are untrusted content and are size-limited. They
may contain prompt injection or PII and receive policy evaluation before being
sent upstream.

### 5.2 Transformations

- redact with typed markers: `[REDACTED:CPF]`;
- stable session pseudonyms: `[EMAIL_1]`, `[PERSON_1]` where supported;
- replace vault references with safe capability descriptions;
- omit forbidden metadata/fields;
- deny a request when content cannot be safely parsed or transformed.

Transformation happens on the canonical representation. The gateway serializes
the transformed representation; it never forwards the original raw body after
sanitizing a copy.

### 5.3 Opaque reference behavior

A prompt may contain an existing `svref:v1:…` or a client may request a
reference through a Sovereign Vault tool. The gateway validates the reference's
safe metadata and sends only a policy-approved description to the model. It
does not substitute the underlying value.

Example model-visible content:

```text
Credential reference [SVREF_1] is available for the registered
"deploy-production" action. Ask to run that profile; do not request its value.
```

The mapping from `[SVREF_1]` to the real opaque token remains local so the
model's tool call can be reconstructed and policy-checked without exposing
internal resource identity unnecessarily.

### 5.4 Unsupported content

Images, audio, PDFs, binary attachments, remote URLs, and provider-native tools
are denied initially unless a dedicated parser and policy exist. Extracting
text with a client-controlled or third-party parser before the gateway does not
make it trusted; extracted text is still scanned, while extraction itself
remains outside gateway coverage unless routed through a registered profile.

## 6. Provider transport

After ingress mediation, the gateway supplies the broker with:

- registered route ID;
- sanitized provider-format request;
- request deadline and limits;
- execution lease tied to the audit intent;
- no provider credential bytes.

The broker validates host/method/path, resolves DNS under ADR-0009 controls,
injects the vault credential, disables redirects unless registered, and returns
a bounded byte/event stream. Authentication headers and upstream request bodies
are never logged.

Retries are disabled by default for requests containing tool continuations or
non-idempotent provider extensions. Any enabled retry has a policy-defined
budget and one request lineage in audit.

## 7. Egress sanitization

### 7.1 Text

Provider text is untrusted and may repeat input PII or secrets. It is scanned
and transformed before client release. Streaming uses Unicode-safe carry-over
buffering so an identifier divided across network chunks is not missed.

Session depseudonymization for local user display is a separate destination
policy. It is never applied before another model call and never changes a
broker-only reference into plaintext.

### 7.2 Tool calls

Tool names and complete structured arguments are accumulated before release to
the client. The runtime evaluates:

- whether the tool is registered for this adapter/principal;
- argument schema and limits;
- referenced resources and exposure class;
- destination/profile/tool binding;
- required consent.

The gateway may return an allowed tool call, a sanitized tool call, or a safe
denial result. It does not execute the tool; execution goes through MCP router,
process broker, or a client-native surface with adapter hooks.

### 7.3 Errors and headers

Upstream error bodies are untrusted. The gateway maps them to safe errors and
may expose only registered status/code fields. It strips auth, request IDs that
encode provider account data, set-cookie, location, server internals, and
unapproved headers.

## 8. Protocol mapping requirements

### Responses ↔ provider Chat Completions

AnyModel's translator can supply fixtures, but the Rust implementation must
cover and test:

- system/developer/user/assistant roles;
- text content arrays without flattening non-text blocks silently;
- function calls and outputs with stable IDs;
- parallel tool calls;
- finish/stop reasons;
- usage fields;
- streaming event order and terminal event;
- provider quirks selected by registered route, not request input.

Reasoning content is not forwarded across incompatible protocols by default.
Dropping it is recorded as an explicit compatibility transformation, never a
silent operation.

### Anthropic Messages ↔ canonical model

Required mappings:

- system blocks remain system instructions;
- `text`, `tool_use`, and `tool_result` retain ordering;
- tool IDs remain stable across continuation;
- `stop_reason` maps without inventing success;
- SSE events preserve content-block lifecycle;
- unsupported blocks deny with their type, not their content.

## 9. Limits

Recommended conservative defaults, finalized by evaluation:

- request body: 8 MiB;
- text fragment: 1 MiB;
- tool schema total: 1 MiB;
- number of messages/input items: 2,048;
- tools: 128;
- nesting depth: 64;
- concurrent requests per principal: 4;
- response: 16 MiB;
- wall timeout: 120 seconds, separately configurable for approved routes;
- streaming boundary buffer: detector-defined and globally capped.

Limit errors occur before forwarding and do not echo body excerpts.

## 10. Health and observability

`/health` reports only locked/ready/degraded and schema version. An authenticated
diagnostic endpoint/CLI may report adapter identity, active policy digest,
supported APIs, registered route IDs, and audit health. It must not reveal keys,
paths, prompts, findings, or raw upstream failures.

Metrics use counts, byte buckets, duration histograms, denial codes, sanitizer
counts, and active streams. Labels are bounded to prevent sensitive high-cardinality
values.

## 11. Acceptance criteria

- Both OpenAI endpoints and Anthropic Messages pass versioned local conformance
  fixtures in streaming and non-streaming modes.
- Provider fixture servers prove the original secret/PII never arrived.
- Client credentials are rejected when missing, invalid, expired, or revoked.
- Unknown fields/blocks cannot bypass sanitization through alternate encoding.
- Tool calls are never released before complete argument policy evaluation.
- Chunk-split PII and Unicode edge cases are filtered.
- Disconnect, timeout, parser failure, audit failure, and locked-vault paths
  fail closed with correct partial-outcome audit.
- No test uses ambient real provider credentials.

