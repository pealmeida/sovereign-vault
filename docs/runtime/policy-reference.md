# Runtime Policy Reference

## 1. Format and ownership

Version 1 uses TOML because the Rust workspace and Codex configuration already
use it. Policy is operator-owned control-plane state; model/tool requests cannot
modify it. The active document is authenticated with vault-managed integrity
material or stored inside an encrypted vault configuration container.

```toml
schema = 1
default_effect = "deny"
policy_id = "personal-default"

[limits]
request_bytes = 8_388_608
fragment_bytes = 1_048_576
response_bytes = 16_777_216
concurrent_requests_per_principal = 4
request_timeout_ms = 120_000
consent_timeout_ms = 120_000
stream_boundary_bytes = 256
```

The parser rejects unknown top-level keys by default. Schema migrations are
explicit and never reinterpret a prior rule silently.

## 2. Rule model

```toml
[[rule]]
id = "redact-pii-to-cloud"
priority = 100

[rule.match]
destination_kind = ["llm_provider"]
labels_any = ["pii.email", "pii.cpf", "pii.cnpj", "pii.card", "pii.phone"]

[rule.effect]
access = "allow"
exposure = "pseudonymize"
consent = "none"
audit = "required"
```

### Match fields

- `principal_ids`, `principal_kinds`, `adapter_ids`;
- `transports`, `operations`, `origin_kinds`;
- `destination_kinds`, `destination_ids`, `host_globs`, `path_prefixes`,
  `methods`;
- `provider_ids`, `model_globs`;
- `mcp_server_ids`, `mcp_tool_globs`;
- `process_profile_ids`;
- `container_globs`, `resource_kinds`, `exposure_classes`;
- `media_types`, `fragment_roles`;
- `labels_all`, `labels_any`, `labels_none`;
- `classification_states` (`low`, `elevated`, `unknown`);
- `min_auth_strength`, `session_max_age_seconds`;
- optional trusted local time window.

Glob syntax is defined once and path-aware. Regex is not accepted in version 1.
Request-supplied arbitrary attributes cannot be used in an allow rule unless a
trusted adapter registration declares and validates them.

### Effects

```toml
[rule.effect]
access = "allow"          # allow | deny
exposure = "redact"       # raw | redact | pseudonymize | omit | reference-only | execute-only
consent = "approval"      # none | approval | otp | deny-if-unavailable
audit = "required"
route = "provider:zai"
max_uses = 1
ttl_seconds = 120
```

`raw` is permitted only for data whose configured exposure class allows raw
release. A policy rule cannot turn broker-only or non-exportable material into
raw data.

## 3. Composition

- Higher numeric priority is evaluated first for diagnostic ordering, not for
  bypassing deny-overrides.
- Any matching `access = "deny"` denies.
- Exposure joins toward the more restrictive representation.
- Consent joins toward the stronger requirement.
- Numeric limits join by minimum.
- Destination sets intersect.
- Route selection must resolve to exactly one registered route; ambiguity
  denies.
- No matching allow after invariant/scope enforcement means deny.

## 4. Reference classes

```toml
[[reference_class]]
id = "provider-key"
exposure = "execute-only"
allowed_operations = ["provider.request"]
default_ttl_seconds = 3600
max_ttl_seconds = 86400
max_uses = 1000
durable = false

[[reference_class]]
id = "signing-key"
exposure = "execute-only"
allowed_operations = ["vault.sign"]
default_ttl_seconds = 300
max_uses = 1
durable = false
```

## 5. Provider routes

```toml
[[provider_route]]
id = "zai-production"
protocol = "openai-chat"
base_url = "https://api.z.ai/api/coding/paas/v4"
credential_ref = "vault://providers/zai/api-key"
allowed_models = ["glm-5.2", "glm-5.1"]
allowed_methods = ["POST"]
allowed_path_prefixes = ["/chat/completions", "/models"]
follow_redirects = false
request_timeout_ms = 120_000
max_response_bytes = 16_777_216
```

`credential_ref` is control-plane configuration and is never returned through
the public reference registry. Route host resolution uses broker SSRF controls.

## 6. External MCP registrations

```toml
[[mcp_server]]
id = "issue-tracker"
transport = "stdio"
command = "C:/Program Files/IssueMCP/issue-mcp.exe"
args = ["serve"]
allowed_tools = ["issues.search", "issues.comment"]
denied_tools = ["issues.delete", "admin.*"]
environment_allowlist = ["SYSTEMROOT", "TEMP"]
result_policy = "external-mcp-default"
require_schema_approval = true
```

Remote registrations additionally specify exact HTTPS origin, authentication
reference, redirect policy, and certificate defaults. Secrets are not placed in
the stdio server environment unless a separate execution-only injection mapping
explicitly permits it.

## 7. Process profiles

```toml
[[process_profile]]
id = "deploy-production"
executable = "C:/Program Files/Acme/deploy.exe"
executable_sha256 = "<pinned digest or omitted with explicit publisher policy>"
working_directory_roots = ["D:/Code/approved-projects"]
argument_schema = "schemas/deploy-production.schema.json"
fixed_args = ["deploy"]
network_hosts = ["deploy.acme.example"]
allow_children = false
timeout_ms = 300_000
max_stdout_bytes = 2_097_152
max_stderr_bytes = 1_048_576

[[process_profile.secret]]
parameter = "credential"
vault_ref = "vault://deploy/acme-token"
injection = "stdin-json-field"
field = "token"
```

No rule accepts an executable or shell command supplied by the model.

## 8. Examples

### PII in prompts

```toml
[[rule]]
id = "cloud-prompt-pii"
[rule.match]
origin_kinds = ["user_prompt", "plugin_content", "native_tool_result"]
destination_kinds = ["llm_provider"]
labels_any = ["pii.*"]
[rule.effect]
access = "allow"
exposure = "pseudonymize"
consent = "none"
audit = "required"
```

### Never send vault keys to a model

```toml
[[rule]]
id = "non-exportable-keys"
[rule.match]
resource_kinds = ["transit_key", "signing_key", "provider_credential"]
destination_kinds = ["llm_provider", "external_mcp"]
[rule.effect]
access = "allow"
exposure = "reference-only"
consent = "approval"
audit = "required"
```

The runtime still enforces the resource's immutable exposure class. This rule
cannot authorize raw release.

### Deny unregistered shell

```toml
[[rule]]
id = "deny-arbitrary-process"
[rule.match]
operations = ["process.exec_arbitrary", "shell.command"]
[rule.effect]
access = "deny"
audit = "required"
```

### Filter external MCP results

```toml
[[rule]]
id = "external-mcp-egress"
[rule.match]
origin_kinds = ["external_mcp_result", "external_mcp_resource"]
destination_kinds = ["client", "llm_provider"]
[rule.effect]
access = "allow"
exposure = "redact"
consent = "none"
audit = "required"
```

## 9. Administration

Required CLI/UI operations:

```text
sv policy validate <file>
sv policy diff <active> <candidate>
sv policy activate <file>
sv policy rollback <version>
sv policy explain --request <safe-fixture.json>
sv policy list-versions
```

`explain` operates on synthetic or already sanitized fixtures and returns rule
IDs and effects, not detector findings or secret values. Activation displays a
semantic summary: newly allowed destinations, weaker/stronger transformations,
new profiles, removed denies, and changed limits.

## 10. Validation requirements

- unique IDs and supported schema;
- no unknown fields;
- all referenced routes/profiles/schemas exist;
- routes use approved schemes and exact hosts;
- no raw exposure for immutable restricted classes;
- no zero/unbounded size, time, or concurrency values;
- process commands are absolute and contain no shell indirection;
- all allow rules are reachable and all ambiguities reported;
- policy canonical digest is stable across formatting changes.

