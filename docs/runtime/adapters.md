# Client Adapter Specification

## 1. Adapter contract

An adapter configures a client to use the LLM gateway and/or MCP router and
reports which native surfaces remain outside mediation. It contains no provider
key and no policy logic.

Every adapter must implement:

1. `detect` — identify client/version/config locations without mutation;
2. `plan` — show exact configuration changes and coverage impact;
3. `apply` — write only after explicit user action, preserving unrelated config;
4. `verify` — issue local synthetic requests and confirm authenticated routing;
5. `status` — report endpoint, identity, policy digest, MCP route, hooks, and
   known bypasses;
6. `remove` — restore only adapter-owned settings;
7. `doctor` — detect direct provider keys/base URLs and non-routed MCP servers.

Generated client credentials are scoped, revocable, and stored using the
client's safest supported local mechanism. They authenticate only to the local
runtime.

## 2. Coverage matrix

| Surface | LLM base URL | MCP router | Hook | Process broker |
|---|---:|---:|---:|---:|
| direct prompt | primary | no | optional provenance | no |
| plugin content before model | primary if same API route | possible | provenance/warning | no |
| native file read sent to model | primary on next request | if MCP tool | action control/provenance | registered reader only |
| arbitrary shell | output filtered only on next model request | if routed tool | block/redirect when supported | only registered profiles |
| external MCP result | gateway catches model-bound copy | primary | bypass warning | stdio server launch only |
| provider credential | client never receives | no | no | provider broker |

No adapter may report “fully protected” solely because the base URL is set.

## 3. Codex adapter

### Intended integration

- Point Codex model traffic at the local OpenAI-compatible endpoint.
- Register only `sv-mcp-router` as the Sovereign runtime MCP entry.
- Use Codex hooks, where supported by the installed version, for provenance,
  policy warnings, and defense-in-depth around native tools.
- Keep Codex authentication to the local gateway separate from provider auth.

Conceptual generated configuration:

```toml
# Exact keys must be selected by version probe against the installed Codex.
openai_base_url = "http://127.0.0.1:<port>/v1"

[mcp_servers.sovereign-runtime]
command = "sovereign-vault"
args = ["mcp-router-stdio", "--adapter", "codex"]
env = { SV_CLIENT_ID = "<non-secret-id>" }
```

The adapter stores the local bearer token in a protected client credential
store or supplies it through an authenticated local bootstrap channel. It does
not write provider keys to `config.toml` or project `.env` files.

### Verification

- synthetic prompt marker appears sanitized at a local provider fixture;
- Codex sees only router MCP tools intended by policy;
- native tool/file/shell hooks produce provenance or a declared coverage gap;
- direct OpenAI/provider configuration is absent or warned;
- lock causes model and secret-backed tool calls to fail closed.

## 4. Claude Code adapter

### Intended integration

- Point Anthropic API traffic at the gateway's `/v1/messages` base.
- Supply a local runtime token in the client-supported auth variable/header;
  never substitute the real Anthropic key.
- Register `sv-mcp-router` as the MCP entry.
- Install UserPromptSubmit/PreToolUse/PostToolUse-equivalent hooks when supported
  to add provenance and block/redirect registered actions.

Conceptual environment for a launched session:

```text
ANTHROPIC_BASE_URL=http://127.0.0.1:<port>
ANTHROPIC_AUTH_TOKEN=<local-runtime-token>
```

The adapter must probe the installed Claude Code version and verify the exact
variables and hook schemas before writing configuration. If a version sends any
model traffic outside the configured base URL, status reports partial coverage.

The existing AnyModel `claude -p <prompt>` engine is not reused for sensitive
prompt handling because it places prompt text in the process argument list.

### Verification

- system/messages/tool-use/tool-result streaming round trips through a fixture;
- hooks cannot leak bodies in their own logs;
- unregistered shell actions are denied or explicitly reported as uncovered;
- external MCP entries outside the router are detected.

## 5. OpenCode adapter

### Intended integration

- Define a local OpenAI-compatible provider whose base URL is the gateway.
- Register the router as the enabled MCP server and disable/directly flag other
  MCP entries according to policy.
- Use supported request/tool hooks for provenance and bypass detection.

Conceptual configuration shape:

```jsonc
{
  "provider": {
    "sovereign": {
      "options": {
        "baseURL": "http://127.0.0.1:<port>/v1",
        "apiKey": "<local-runtime-token>"
      }
    }
  },
  "mcp": {
    "sovereign-runtime": {
      "type": "local",
      "command": ["sovereign-vault", "mcp-router-stdio", "--adapter", "opencode"]
    }
  }
}
```

Exact fields are version-probed. The adapter must determine whether the chosen
provider path uses Responses or Chat Completions and select only a gateway mode
with passing conformance tests.

## 6. Generic MCP adapter

The generic adapter provides a stdio command:

```text
sovereign-vault mcp-router-stdio --client-id <id>
```

Bootstrap credentials are obtained through a protected per-client config or
one-time pairing process. The command must not print the credential, prompt
body, tool arguments, or results to stderr.

Generic MCP alone covers only routed MCP operations. It does not protect direct
prompt/model traffic, native tools, or shell commands. Documentation and
`status` always display that limitation.

## 7. Generated management commands

Planned user-facing flow:

```text
sv adapter detect
sv adapter plan codex
sv adapter apply codex
sv adapter verify codex
sv adapter status --all
sv adapter doctor codex
sv adapter remove codex
```

`apply` displays files/settings that will change and does not overwrite unknown
keys. Backups are permission-restricted and contain no provider credentials.

## 8. Hooks

Hooks can:

- attach origin metadata to prompt/tool-result fragments;
- block obvious direct provider/MCP invocation;
- convert an approved high-level action to a registered broker profile;
- notify runtime of native file/shell actions for audit context;
- sanitize hook-visible output before it re-enters a prompt.

Hooks must not:

- hold provider or application credentials;
- become the sole policy evaluator;
- log prompt/tool bodies;
- attempt reversible secret substitution;
- claim control over actions the client executes without a blocking hook.

## 9. Adapter acceptance criteria

- Version detection and generated config are idempotent.
- Apply/remove preserve unrelated settings and handle dirty/invalid config
  without destructive rewrite.
- Local auth works with no provider key in client process environment/config.
- Synthetic data proves supported model traffic reaches the gateway.
- Router tool inventory matches policy and external direct MCP entries are
  reported.
- Coverage status explicitly addresses all five exposure routes.
- Unsupported client versions fail with instructions rather than partial silent
  configuration.

