# AnyModel Reference Adoption

## 1. Decision

AnyModel is a protocol/reference input, not the trusted `sv-llm-gateway` data
plane. Reuse is limited to material that can be independently reviewed,
licensed, ported, and tested:

- Responses-to-Chat request mappings;
- Chat-to-Responses streaming event mappings;
- provider registry concepts;
- provider-quirk fixtures;
- model prefix/alias behavior;
- compatibility test scenarios.

Its Node server, direct engine, MCP spawning path, environment credential
loading, and plaintext job logging are not included in the trusted runtime.

## 2. Provenance prerequisites

Before copying or deriving implementation material:

1. repair or obtain a verifiable AnyModel Git checkout; the inspected working
   tree had an invalid `HEAD`;
2. identify the exact upstream OpenAI Codex plugin commit/version used;
3. restore Apache-2.0 `LICENSE` and required `NOTICE` attribution;
4. mark modified derived files as required by the license;
5. create a provenance manifest containing source path/repository, commit,
   license, copied concepts/files, port date, and reviewer;
6. review any provider-specific terms separately from code licensing.

This is an engineering compliance prerequisite, not legal advice.

## 3. Extraction method

Do not mechanically vendor the Node modules into the Rust crate. Instead:

1. capture input/output fixture pairs with synthetic data;
2. document the semantic behavior each fixture represents;
3. add negative fixtures for fields AnyModel currently drops or flattens;
4. implement the canonical mapping independently in Rust;
5. run differential tests against the reference only for non-sensitive
   synthetic fixtures;
6. promote a provider quirk only after a provider fixture demonstrates it;
7. retain a compatibility note when behavior intentionally differs for safety.

## 4. Required additional fixtures

The reference test set must be expanded before it can define gateway behavior:

- text content split across multiple blocks;
- developer/system role ordering;
- parallel and interleaved tool calls;
- tool-call ID delivered after the first stream delta;
- invalid/missing tool IDs and arguments;
- multiple choices/content blocks;
- finish reasons and provider errors;
- UTF-8 split across network chunks;
- PII split across SSE chunks;
- unknown/non-function tool types;
- images/audio/binary blocks, expected to deny initially;
- disconnect, timeout, oversized stream, malformed SSE, and missing terminal
  event;
- headers/auth stripping and redirect denial;
- ambient credential isolation.

## 5. Registry migration

AnyModel's registry concept becomes authenticated Sovereign Vault route policy.
The target registry adds:

- stable route ID separate from provider ID;
- upstream protocol and exact allowed paths/methods;
- vault credential reference;
- models allowlist;
- SSRF/redirect/timeout/size settings;
- supported feature matrix;
- quirk IDs and tested fixture version;
- enabled/revoked state and configuration digest.

Provider or model prefix from a client selects only among registered aliases; it
cannot inject a base URL or environment-key name.

## 6. Security differences from the reference

The Rust gateway intentionally differs by requiring:

- inbound per-client authentication;
- no provider credentials in the client or shim environment;
- bounded body/stream/concurrency/time;
- runtime policy and consent before forwarding;
- ingress and egress sanitization;
- complete tool-argument authorization;
- authenticated intent/outcome audit with no plaintext body;
- fail-closed unknown content;
- no direct arbitrary shell agent loop.

## 7. Acceptance

AnyModel reference adoption is complete only when provenance is recorded,
license obligations are satisfied, every adopted semantic rule has a synthetic
fixture, and no Node runtime is necessary to operate the product gateway.

