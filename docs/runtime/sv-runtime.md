# `sv-runtime` Specification

## 1. Responsibility

`sv-runtime` is the transport-independent decision and orchestration layer. It
receives normalized requests from the LLM gateway, MCP router, and process
broker and returns an executable plan or a denial. It owns no network listener
and does not understand provider-specific JSON beyond normalized content types.

The crate contains four primary subsystems:

- policy engine;
- opaque reference registry;
- consent binding and grant validation;
- audit orchestration.

It reuses `sv-core` for vault operations, `sv-privacy` for detection/redaction,
and `sv-audit` for authenticated persistence. Proposed `sv-classify` may later
provide an elevation result without becoming the policy authority.

## 2. Dependency direction

```text
sv-llm-gateway ─┐
sv-mcp-router ──┼──> sv-runtime ──> sv-core
sv-process-broker┘        │        ├─> sv-privacy
                         │        ├─> sv-audit
                         │        └─> sv-classify (optional, proposed)
                         └─ no dependency back to transports
```

`sv-runtime` must not depend on Tauri. Consent is an injected trait implemented
by desktop, terminal, or a test controller.

## 3. Canonical types

The following sketches define semantic contracts, not final source syntax:

```rust
struct Principal {
    id: PrincipalId,
    kind: PrincipalKind,       // client, adapter, mcp_server, process_profile
    scopes: Vec<Scope>,
    session_id: SessionId,
}

struct MediationRequest {
    request_id: RequestId,
    principal: Principal,
    transport: TransportKind,
    operation: Operation,
    origin: Origin,
    destination: Destination,
    fragments: Vec<DataFragment>,
    references: Vec<ReferenceUse>,
    attributes: BTreeMap<String, ScalarValue>,
    deadline: Instant,
}

struct DataFragment {
    fragment_id: FragmentId,
    media_type: MediaType,
    role: FragmentRole,
    provenance: Provenance,
    content: SensitiveBytes,
}

enum DecisionEffect {
    Deny,
    Allow,
    Transform(TransformationPlan),
    RequireConsent(ConsentRequirement),
    ExecuteOnly(ExecutionConstraint),
}

struct MediationPlan {
    policy_version: PolicyVersion,
    effects: Vec<DecisionEffect>,
    transformed_fragments: Vec<PreparedFragment>,
    reference_metadata: Vec<ResolvedReferenceMetadata>,
    consent_binding: Option<ConsentBinding>,
    audit_intent: AuditIntent,
    limits: EffectiveLimits,
}
```

`SensitiveBytes` should minimize cloning and implement zeroization where the
underlying buffer permits it. This reduces lifetime but is not evidence of
complete memory erasure across allocators and dependencies.

## 4. Policy engine

### 4.1 Inputs

Policy evaluates immutable facts:

- principal ID/kind/scopes and adapter identity;
- session age and authentication strength;
- transport and endpoint;
- operation and requested capability;
- origin/provenance of each fragment;
- destination provider/model, MCP server/tool, process profile, host/method;
- vault container/file mode and secret exposure class;
- detected labels and optional classification state;
- reference constraints;
- registered tool schema/profile/route digest;
- content/media type and bounded sizes;
- time and explicit operator state.

Model text, MCP descriptions, plugin annotations, and request-supplied labels
are untrusted claims. They may provide provenance hints but cannot grant access.

### 4.2 Evaluation order

1. Load one immutable, validated policy snapshot.
2. Apply hard platform invariants and size limits.
3. Evaluate explicit denies.
4. Enforce identity scopes and registrations.
5. Determine mandatory exposure constraints from secret/reference class.
6. Add configured redaction/omission/pseudonymization transformations.
7. Join optional classification as elevation-only input.
8. Derive the consent floor.
9. Calculate final route and execution limits.
10. Return a plan tied to the policy snapshot digest.

There is no “first allow wins.” Denies override allows, and transformations and
consent compose independently. `ANONYMIZED + APPROVAL`, for example, retains
masking and adds approval.

### 4.3 Decision lattice

The effective result is the join of independent axes:

```text
access:        deny > scoped allow
exposure:      non-exportable > execute-only > reference-only > transformed > raw
consent:       deny-if-unavailable > OTP > approval > none
audit:         durable intent required
limits:        most restrictive value wins
```

An `allow` rule cannot weaken a higher exposure or consent requirement.

### 4.4 Policy snapshot

Each request uses exactly one policy version. Reload creates a new immutable
snapshot for later requests. Long-running streams retain their starting policy
unless a revocation/kill-switch event requires cancellation. The intent event
records the policy digest.

Invalid policy prevents activation; the last valid policy can remain active
only if explicitly configured. If no valid policy has ever loaded, protected
operations deny.

## 5. Reference registry

### 5.1 Purpose

The registry lets the model name a protected resource without receiving its
value. It is distinct from `agents.json`: agent identity controls who asks;
references constrain what a particular handle may do.

### 5.2 Reference format

External form:

```text
svref:v1:<base64url(random-256-bit-id)>
```

The token is random and carries no resource name, path, type, or ciphertext.
It is not a capability by possession alone; authenticated registry lookup and
policy are always required.

### 5.3 Registry entry

```rust
struct ReferenceEntry {
    id_hash: [u8; 32],
    resource: InternalResourceId,
    class: ExposureClass,
    owner_principal: Option<PrincipalId>,
    audience: Vec<DestinationSelector>,
    allowed_operations: BTreeSet<OperationKind>,
    created_at: Timestamp,
    expires_at: Timestamp,
    session_id: Option<SessionId>,
    max_uses: Option<u32>,
    use_count: u32,
    metadata_projection: SafeMetadata,
    policy_version: PolicyVersion,
    revoked: bool,
}
```

Persist only keyed token hashes, like agent tokens. Session references remain
memory-only by default. Durable references require encrypted/authenticated
registry storage and explicit operator creation.

### 5.4 Resolution

Resolution occurs in two phases:

1. **Metadata resolution:** runtime validates token hash, principal, audience,
   operation, expiry, revocation, and usage. It returns safe metadata only.
2. **Material resolution:** the final trusted broker requests the internal
   resource for the already approved operation digest. Secret bytes are never
   returned to gateway/router/adapters as general data.

Reference use counters must be updated atomically with execution authorization.
Single-use references are consumed before execution; failure semantics must
prevent replay while reporting whether an external action may have happened.

### 5.5 Safe model representation

The runtime may expose:

```json
{
  "reference": "svref:v1:…",
  "kind": "provider_credential",
  "allowed_actions": ["provider.request"],
  "destination": "provider:production",
  "expires_at": "2026-08-14T18:30:00Z"
}
```

It must not expose secret length, prefix/suffix, vault path, checksum, or a
description copied from protected content.

## 6. Consent binding

### 6.1 Canonical operation

Consent applies to a canonical `OperationDescriptor`:

```rust
struct OperationDescriptor {
    principal_id: PrincipalId,
    session_id: SessionId,
    operation: OperationKind,
    resources: Vec<InternalResourceId>,
    destination: CanonicalDestination,
    parameters_digest: KeyedDigest,
    content_digest: KeyedDigest,
    transformation_digest: Digest,
    route_or_schema_digest: Digest,
    policy_digest: Digest,
    executable_digest: Option<Digest>,
    issued_at: Timestamp,
    expires_at: Timestamp,
    nonce: Nonce,
}
```

Canonicalization is versioned. Maps are sorted; default values are explicit;
URLs are normalized without broadening path semantics; arguments remain typed;
unknown fields cause an unsupported-feature error rather than disappearing.
Sensitive content uses an HMAC/keyed digest so low-entropy values cannot be
confirmed through an offline public hash dictionary.

### 6.2 User prompt

The consent UI shows the minimum information required to make a decision:

- requesting client and authenticated principal;
- action and resource label chosen locally;
- exact provider/MCP server/process profile and target host where relevant;
- whether raw, redacted, reference-only, or execute-only data is involved;
- number and coarse categories of transformed fragments, subject to privacy
  policy;
- expiry and whether the request is one-shot.

OS notifications remain attention signals only under ADR-0014. Approval occurs
inside the trusted UI/terminal.

### 6.3 Grant

A grant contains the descriptor digest, decision, actor, timestamp, expiry, and
unique grant ID authenticated with a runtime subkey. Grants are one-shot by
default. A reusable lease must constrain destination, action, reference set,
maximum uses, duration, and policy version, and must be independently revocable.

Immediately before execution, runtime recomputes the descriptor and compares it
in constant time. Any changed field, expired grant, policy reload, schema/profile
change, or session change denies.

## 7. Audit orchestration

### 7.1 Two-event minimum

Each operation has at least:

1. `runtime.intent`: durable before egress/execution;
2. `runtime.outcome`: success, denied, failed, cancelled, timeout, or
   `executed_audit_incomplete`.

Optional stage events are avoided unless necessary; metrics should be
aggregated without creating a detailed behavioral transcript.

### 7.2 Intent fields

- event and request IDs;
- parent request/tool/stream ID;
- principal and adapter IDs;
- operation, origin type, destination type and safe identifier;
- keyed resource/reference identifiers;
- policy, route, schema, profile, and operation digests;
- configured/effective exposure and consent modes;
- transformation types and counts;
- byte-count buckets and configured limits;
- consent grant ID or denial reason code;
- timestamp and audit schema version.

### 7.3 Outcome fields

- linked intent ID;
- outcome and stable error code;
- external status class, never raw error body;
- input/output byte-count buckets;
- redaction/omission counts;
- coarse stage timings;
- retry count and idempotency state;
- cancellation/timeout/partial-execution markers.

### 7.4 Forbidden fields

Prompt text, secret values, unredacted findings, raw headers, command output,
tool results, model responses, query strings, authorization data, numeric
classifier score, and reversible reference mappings never enter audit.

## 8. Public runtime interfaces

Suggested traits:

```rust
trait PolicyEvaluator {
    async fn plan(&self, request: &MediationRequest) -> Result<MediationPlan>;
}

trait ConsentProvider {
    async fn decide(&self, request: ConsentPrompt) -> ConsentDecision;
}

trait ReferenceResolver {
    async fn metadata(&self, use_: &ReferenceUse) -> Result<ResolvedReferenceMetadata>;
    async fn authorize_material_use(&self, grant: MaterialUseGrant) -> Result<MaterialLease>;
}

trait AuditSink {
    async fn intent(&self, intent: AuditIntent) -> Result<IntentReceipt>;
    async fn outcome(&self, receipt: IntentReceipt, outcome: AuditOutcome) -> Result<()>;
}
```

Transport components receive only `MediationPlan` and typed execution leases;
they cannot ask the runtime for arbitrary secret bytes.

## 9. Error contract

Errors are stable codes with safe metadata:

- `auth_required`, `auth_invalid`, `principal_revoked`;
- `scope_denied`, `policy_denied`, `policy_unavailable`;
- `unsupported_content`, `invalid_structure`, `limit_exceeded`;
- `reference_invalid`, `reference_expired`, `reference_audience_denied`;
- `consent_required`, `consent_denied`, `consent_expired`,
  `consent_binding_mismatch`;
- `audit_unavailable`;
- `route_denied`, `profile_denied`, `destination_denied`;
- `upstream_timeout`, `upstream_protocol_error`;
- `executed_audit_incomplete`.

Messages never echo rejected content or credentials.

## 10. Required tests

- policy determinism and deny-overrides property tests;
- elevation-only composition for every mode combination;
- reference expiry, audience, replay, revocation, and collision tests;
- canonicalization stability and mutation-invalidates-consent tests;
- audit-before-release ordering tests with injected failures;
- no-sensitive-data snapshot tests over errors/audit/traces;
- concurrent reference consumption and policy reload tests;
- fuzzing for policy documents and canonical descriptors.

