# Runtime Mediation Implementation Specification

> **Status: accepted architecture; implementation pending.** Nothing in this folder
> describes a current capability unless it links explicitly to existing code.
> These documents must not be used to expand thesis claims before implementation
> and evaluation.

This folder is the implementation contract for the Sovereign Vault runtime
mediation stack introduced by [ADR-0015](../adr/0015-runtime-mediation-stack.md).
Its goal is to let a user employ sensitive data and keys from common CLIs and
IDEs without placing raw protected values in model context.

## Read in this order

1. [Architecture](architecture.md) — components, trust boundaries, and flows.
2. [Security model](security-model.md) — threats, invariants, and bypass limits.
3. [`sv-runtime`](sv-runtime.md) — policy engine, reference registry, consent
   binding, and audit orchestration.
4. [Policy reference](policy-reference.md) — configuration schema and examples.
5. [`sv-llm-gateway`](sv-llm-gateway.md) — OpenAI and Anthropic APIs plus
   ingress/egress sanitization.
6. [`sv-mcp-router`](sv-mcp-router.md) — local tools, external MCP mediation,
   and result filtering.
7. [`sv-process-broker`](sv-process-broker.md) — registered application
   profiles, secret injection, and output filtering.
8. [Adapters](adapters.md) — Codex, Claude Code, OpenCode, and generic MCP.
9. [Internal protocols](protocols.md) — common envelopes, identifiers, errors,
   and streaming contracts.
10. [Implementation roadmap](implementation-roadmap.md) — work packages,
    sequencing, migration, and acceptance gates.
11. [Testing and evaluation](testing-and-evaluation.md) — conformance,
    adversarial, privacy, performance, and DSR evidence.
12. [Operations](operations.md) — bootstrap, deployment, rotation, diagnostics,
    and incident handling.
13. [AnyModel reference adoption](anymodel-reference.md) — provenance,
    licensing, fixtures, and the boundary between reusable compatibility work
    and the trusted Rust data plane.

## Component map

| Component | Responsibility | Must not do |
|---|---|---|
| `sv-runtime` | Decide whether and how data may move | Speak provider- or MCP-specific wire formats |
| `sv-llm-gateway` | Terminate model APIs and sanitize traffic | Reveal provider credentials or bypass runtime policy |
| `sv-mcp-router` | Mediate local and external MCP capabilities | Trust server descriptions or results as safe content |
| `sv-process-broker` | Run registered profiles with late-bound secrets | Offer a general-purpose privileged shell |
| `adapters/*` | Configure each client and report coverage | Become the source of security policy |

## Existing code reused

| Existing capability | Planned consumer |
|---|---|
| `sv-core` vault, agents, transit, signing, broker | all trusted execution paths |
| `sv-privacy::scan/redact` | `sv-runtime` and gateway/router/broker filters |
| `sv-audit` authenticated chain | runtime audit sink |
| `sv-mcp` local Sovereign Vault tools | `sv-mcp-router` local backend |
| desktop approval/OTP controller | runtime consent provider |
| `sv-http` loopback conventions | local health/bootstrap where appropriate |

`sv-classify` from proposed ADR-0013 is an optional later input to the policy
engine. The initial runtime must work with deterministic labels and configured
rules even if adaptive classification has not been implemented.

## Terminology

- **Principal:** authenticated client, adapter, MCP server, or process profile.
- **Origin:** where a data fragment came from: user prompt, file, tool result,
  MCP resource, vault item, process output, or model response.
- **Destination:** exact provider, model route, MCP server/tool, application
  profile, host, or user-visible output receiving data.
- **Release:** movement of plaintext or derived sensitive content across a
  local trust boundary.
- **Opaque reference:** non-secret handle that lets a model name a resource or
  capability without possessing its value.
- **Late binding:** resolving a reference to protected bytes only inside the
  trusted executor and only after policy and consent succeed.
- **Sanitization:** bounded inspection and transformation of structured content
  before release.
- **Coverage:** the surfaces an adapter demonstrably routes through the stack.

## Non-goals for the first implementation

- OS-level process or memory isolation.
- Interception of applications that are not configured to use the gateway.
- Semantic detection of every form of personal or sensitive data.
- Provider retention or deletion verification.
- Arbitrary command sandboxing.
- Transparent interception of arbitrary TLS traffic.
- RAG, embeddings, vector indexing, or context containers.
