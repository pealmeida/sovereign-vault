# Internal Runtime Protocols

## 1. Purpose

The external APIs evolve independently, but all components must agree on
identity, content, decisions, streaming, and errors. These in-process contracts
prevent each adapter from inventing its own security semantics.

## 2. Identifier rules

| Identifier | Format | Properties |
|---|---|---|
| request | `req_<base32 random>` | unique per external request |
| session | `ses_<base32 random>` | rotates on lock/re-auth |
| principal | existing `ag_…` or typed runtime ID | stable, revocable |
| fragment | `frag_<counter/random>` | unique within request |
| intent | `intent_<base32 random>` | durable audit link |
| consent | `grant_<base32 random>` | unpredictable, one-shot default |
| reference | `svref:v1:<base64url>` | opaque 256-bit random token |

Identifiers never embed names, timestamps, paths, providers, or content hashes.

## 3. Provenance

```rust
struct Provenance {
    origin_kind: OriginKind,
    principal_id: PrincipalId,
    adapter_id: AdapterId,
    parent_request_id: Option<RequestId>,
    source_id: Option<SafeSourceId>,
    trust: ProvenanceTrust, // authenticated, adapter_attested, untrusted
}
```

Adapter-attested provenance is useful for policy but cannot expand scopes. If
metadata is missing, origin becomes `unknown_client_content`, never `public`.

## 4. Content model

```rust
enum Content {
    Text(Utf8Text),
    Json(CanonicalJson),
    ToolCall(ToolCall),
    ToolResult(ToolResult),
    Resource(ResourceDescriptor),
    Image(UnsupportedOrTypedImage),
    Audio(UnsupportedOrTypedAudio),
    Binary(UnsupportedBinary),
}
```

Text preserves role and boundaries. JSON sanitization walks string leaves while
retaining keys and types; policy can deny sensitive key names or particular
paths. Unknown/binary values carry size and media type but are not forwarded by
default.

## 5. Mediation exchange

```rust
struct MediationOutcome {
    request_id: RequestId,
    intent_receipt: IntentReceipt,
    decision: EffectiveDecision,
    prepared: Vec<PreparedFragment>,
    execution_lease: Option<ExecutionLease>,
    limits: EffectiveLimits,
}
```

An `ExecutionLease` is typed for exactly one executor and operation. It cannot
be serialized to an untrusted client and expires quickly.

## 6. Streaming contract

### 6.1 Ingress

External request bodies are bounded before full allocation. JSON API requests
are parsed completely before provider forwarding because policy may depend on
any field. Uploads and multipart content are unsupported initially.

### 6.2 Egress

The provider stream is decoded into semantic events:

- text delta;
- tool name/arguments delta;
- reasoning/metadata delta;
- usage;
- terminal status/error.

The sanitizer maintains:

- a Unicode-safe boundary window for text;
- complete accumulated tool arguments before releasing an executable tool call;
- output and event counts;
- provider-to-client ID mapping;
- a terminal state guaranteeing one outcome audit record.

Text is not emitted until it is outside the detector carry-over window. This
adds bounded latency. On stream failure the unsafely buffered tail is discarded,
the client receives a safe error, and audit records partial release counts.

### 6.3 Backpressure and cancellation

Every hop uses bounded channels. Client disconnect cancels provider/MCP/process
work when safe. If cancellation cannot guarantee that an external action did
not occur, outcome is `unknown_external_outcome`, not `cancelled_without_effect`.

## 7. Destination canonicalization

Destinations are typed:

```rust
enum Destination {
    Llm { route_id, provider_id, model_id },
    Mcp { server_id, tool_or_resource_id, schema_digest },
    Process { profile_id, executable_digest },
    Http { route_id, scheme, host, port, path, method },
    LocalUser { surface },
}
```

Policy never compares free-form URLs or command strings. Canonicalization
retains path boundaries and rejects user-info, fragments, ambiguous hosts,
unsupported schemes, and non-normalized IP forms where relevant.

## 8. Execution lease

```rust
struct ExecutionLease {
    lease_id: LeaseId,
    request_id: RequestId,
    intent_id: IntentId,
    executor: ExecutorId,
    operation_digest: Digest,
    reference_ids: Vec<ReferenceId>,
    destination: CanonicalDestination,
    expires_at: Timestamp,
    nonce: Nonce,
}
```

The broker validates the lease immediately before material resolution. Leases
are not bearer access for arbitrary operations: all fields must match the
broker's locally reconstructed operation.

## 9. Error mapping

Internal stable errors map to each external protocol without leaking protected
content:

| Internal | HTTP | OpenAI-style type | Anthropic-style type | MCP |
|---|---:|---|---|---|
| authentication | 401 | `authentication_error` | `authentication_error` | JSON-RPC error |
| scope/policy deny | 403 | `permission_error` | `permission_error` | tool `isError`/RPC error |
| malformed/unsupported | 400 | `invalid_request_error` | `invalid_request_error` | invalid params |
| consent timeout | 409 | `consent_required` | `permission_error` | typed tool error |
| limit | 413/429 | `rate_limit_error` | `rate_limit_error` | typed tool error |
| upstream | 502/504 | `upstream_error` | `api_error` | typed tool error |
| runtime locked/unavailable | 503 | `service_unavailable` | `api_error` | server error |

Public messages include request ID and a safe reason. Detailed protected
diagnostics remain unavailable rather than being moved to a debug log.

## 10. Versioning

- External compatibility is versioned by endpoint and feature matrix.
- Internal structs carry `schema_version` when persisted or canonicalized.
- Policy, route, MCP schema, process profile, and consent canonicalization each
  have independent digests.
- A compatibility change that affects canonical operation meaning invalidates
  outstanding consents and references whose audience depends on it.

