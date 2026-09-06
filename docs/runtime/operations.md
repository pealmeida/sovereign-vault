# Runtime Operations Guide

## 1. Status

This is the target operational contract. Commands are planned and must not be
presented as available until implemented.

## 2. Bootstrap sequence

1. Install a signed/verified Sovereign Vault build.
2. Initialize/unlock the vault using existing custody flow.
3. Create a dedicated runtime principal and per-adapter identities.
4. Import provider/application credentials directly into encrypted vault
   storage; do not write `.env.runtime`.
5. Register provider routes, external MCP servers, and process profiles.
6. Validate and activate a policy bundle.
7. Start the runtime on loopback/local IPC.
8. Apply one client adapter and run its synthetic verification.
9. Review the coverage report and resolve direct provider/MCP bypass warnings.
10. Enable additional clients/routes/profiles one at a time.

## 3. Startup checks

Runtime refuses protected service when:

- vault/audit verification fails;
- no valid policy is active;
- local listener cannot enforce configured authentication;
- provider route/profile/MCP registration is invalid;
- configuration schema is newer/unknown;
- required consent provider is unavailable for a route that mandates consent.

Degraded startup may expose only authenticated diagnostics and explicitly public
no-vault routes. It never falls back to direct secret release.

## 4. Lock behavior

Locking must:

- stop accepting protected requests;
- cancel or safely drain active provider/MCP/process operations;
- invalidate client sessions, execution leases, consent grants, and session
  references;
- close one-shot secret channels;
- zeroize owned secret buffers where supported;
- stop external stdio MCP servers started by the router;
- append lock/cancellation audit outcomes;
- retain no raw request/response cache.

Processes that cannot be proven terminated are surfaced as an incident. Lock
does not claim to erase secrets already received by another process.

## 5. Credential lifecycle

### Client credentials

- per adapter/device/client;
- stored hashed in the vault registry;
- scopes limited to gateway/router/profile needs;
- revocable without rotating provider credentials;
- rotated on suspected client compromise.

### Provider/application credentials

- stored encrypted under existing vault key hierarchy;
- never exported to adapter configuration;
- destination/profile allowlist mandatory;
- rotated independently;
- reference mappings invalidated on rotation where binding changes;
- broker cache disabled by default or kept memory-only with short TTL.

### Audit keys

Follow existing authenticated chain/checkpoint semantics. Runtime schema changes
must preserve verification and migration before new events are accepted.

## 6. Configuration and permissions

Policy, route, server, and profile control-plane files are encrypted or
authenticated and atomically replaced. Plain project-local files may contain
non-secret adapter IDs and endpoint addresses, not tokens or provider keys.

On Windows, local secret-bearing state uses user-restricted ACLs; on Unix,
owner-only permissions. Permissions reduce accidental access but do not defend
a fully compromised same-user account.

## 7. Diagnostics

Planned commands:

```text
sv runtime status
sv runtime doctor
sv adapter status --all
sv policy list-versions
sv provider test <route> --synthetic
sv mcp-server inspect <id>
sv profile test <id> --synthetic
sv audit verify
```

Diagnostics report safe IDs, versions, state, endpoint reachability, last safe
error code, and coverage. They never print prompt snippets, headers, provider
responses, secret names/values, tool results, or command output.

## 8. Logging and metrics

Default log level records lifecycle and stable error codes only. Raw-body,
header, argv, environment, and content logging do not exist as hidden debug
options. Structured fields are allowlisted.

Metrics:

- requests/outcomes by bounded operation class;
- denial/error codes;
- duration histograms;
- byte-size buckets;
- redaction/omission counts;
- active streams/processes;
- adapter coverage state;
- audit health.

Principal/resource/destination IDs use bounded safe categories or keyed hashes,
not raw high-cardinality strings.

## 9. Backups and recovery

Back up encrypted vault material, authenticated policies/profiles/routes,
identity registry, and audit state using existing vault backup guidance. Do not
back up session references, pseudonym maps, execution leases, consent grants,
temporary channels, or raw traffic.

After recovery:

- re-bootstrap custody as required by current vault limitations;
- revoke/reissue client identities;
- invalidate all prior session/durable references unless explicitly restored
  and verified;
- re-verify routes, MCP schemas, profiles, executable identities, and adapters;
- test only against synthetic fixtures before enabling real providers.

## 10. Upgrade and rollback

Upgrade order:

1. verify backup and audit;
2. stop/lock runtime;
3. install verified binary;
4. validate migrations without activation;
5. activate binary/config atomically;
6. run synthetic self-tests;
7. re-enable adapters/routes gradually.

Rollback is permitted only if the prior binary understands the active storage,
policy, audit, and canonicalization schemas. Otherwise restore through an
explicit migration path; never silently ignore new fields.

## 11. Incident response

### Suspected client/plugin compromise

Lock runtime, revoke that client identity, inspect authenticated audit metadata,
remove adapter config, rotate references/consents, and rotate provider/application
credentials only if their broker boundary may have been crossed.

### Suspected provider-key exposure

Disable route, revoke upstream key, rotate vault entry, invalidate related
references/leases, verify no client config/log contains the canary/value, and
record an incident without copying the key into notes.

### Audit failure

Fail protected requests closed, preserve files, avoid “repairing” the chain in
place, export encrypted evidence, and require operator recovery/verification.

### Process may have executed but outcome is unknown

Stop further profile invocations, preserve safe audit metadata, inspect the
target system using an independent channel, and do not retry automatically.

## 12. Uninstall

Removal order:

1. lock runtime;
2. remove adapters and verify clients no longer point to the endpoint;
3. revoke client identities;
4. disable routes/servers/profiles;
5. uninstall runtime binary/service;
6. retain or securely remove encrypted vault/audit data only through an
   explicit user choice.

Uninstall never deletes vault data by default.

