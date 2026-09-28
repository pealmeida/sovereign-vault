# ADR-0024 — Agent-requested secret entry with runtime injection

- **Status:** Accepted
- **Date:** 2026-09-27
- **Deciders:** pealmeida
- **Design spec:** [`docs/development/specs/2026-09-27-secret-entry-design.md`](../development/specs/2026-09-27-secret-entry-design.md)

## Context

When a project needs a credential, the user has three options today, and each
leaks the value somewhere:

1. Paste it into `.env` or a config file: plaintext on disk, often in git.
2. Paste it into the agent chat: the value enters the model context and the
   transcript.
3. Store it with `vault.write`: the agent can later `vault.read` it, so the
   value still reaches the model context on read-back.

ADR-0009 already established use-without-exposure for keys the vault *uses*
(transit, signing, broker). It does not cover the most common case: an
application that needs an API key **in its own process environment**, while the
agent's job is only to wire that application up.

Two observations from live use shaped the decision. First, the 120 s approval
timeout (ADR-0014, `APPROVAL_TIMEOUT_SECS`) expired twice in a single session
while the user was elsewhere; fetching a key from a provider dashboard takes
longer than that. Second, the OTP code is valid for 120 s (`OTP_TTL_SECS`), and
a resend reuses the code currently displayed instead of issuing a new one, so
once the TTL has passed a slow human answers with a code that has already
expired.

## Decision

Add an agent-initiated, human-completed secret entry flow, and a runtime
injector that is the only egress for these values.

1. **`vault.request_secret`** (new `AccessAction::RequestSecret`). The agent
   names a container, an environment variable, and a purpose. The call returns
   immediately with a `request_id`; the desktop shows an entry modal with the
   container and variable name locked. The modal is the consent; no separate
   approval prompt. Requests live 15 minutes. Only `DIRECT` and `APPROVAL`
   containers are accepted in the MVP; an OTP container would be unreachable
   by `run`, which has no channel to relay a code.
2. **`vault.secret_status`** (new `AccessAction::SecretStatus`) long-polls the
   request and, once stored, returns only metadata: a keyed fingerprint
   (`HMAC-SHA256` under a DEK-derived subkey, truncated to 8 hex), the length,
   and whether an existing key was replaced. The fingerprint reveals equality
   only under the same DEK and can collide at 32 bits of output; it is a visual
   confirmation, not an identifier.
3. **Storage** is one encrypted file per key, `<ENV_VAR>.env-secret`, in the
   named container; the `.env-secret` suffix counts against the 128-character
   file-name limit, so `ENV_VAR` is capped at 117 characters.
4. **Write-only boundary.** A single `secret_file_guard` in `sv-mcp`, evaluated
   before scopes and the mode flow, denies agent `ReadFile`, `WriteFile`, and
   `DeleteFile` on `*.env-secret` in every mode, including `DIRECT`; this part
   of the guard is syntactic — the suffix — and runs before the scope checks.
   The `vault.destroy` denial (`AccessAction::DestroyContainer`) runs the other
   way: scope authorization comes first, so an agent outside the container's
   glob is refused without learning whether it holds a secret, and only inside
   that authorization is the container inspected for a `*.env-secret` — the
   check and the deletion under one lock — and denied with `write_only_secret`
   in every mode; such containers can be destroyed only from the desktop. The
   desktop guard lives in the backend Tauri commands that return or decrypt
   file content (`vault_read_file`, `vault_export_file`), not only in the
   viewer: the value is never displayed anywhere.
5. **`sovereign-vault run -- <cmd>`** resolves the container's keys through an
   internal `vault.resolve_env` method (new `AccessAction::ResolveEnv`, not
   listed in `tools/list`). Every resolve requires a desktop click showing the
   exact argv, cwd, and variable names; there is no "remember" grant. The
   consent binds each key to its internal revision — not to its fingerprint —
   and to the container's generation, so a rotation or a delete-and-recreate
   between the click and consumption makes the resolve fail closed. `run`
   must present an explicit agent identity (`SV_AGENT_ID` +
   `SV_PAIRING_TOKEN`); a process that pairs with only the per-launch pairing
   secret resolves to the unscoped Default agent and is refused with
   `identity_required`. The only injection source is the container's
   `*.env-secret` files; plaintext entries in the container's `.env` are not
   injected. Values reach the child process environment only; on Unix `run`
   calls `exec()`.
6. **Threat model for this feature** is a cooperating but leaky agent. The
   write-only guard holds even against a hostile agent; the `resolve_env` path
   does not, and that limit is declared (see Consequences).

## Consequences

- **Positive.** The common "the app needs `OPENAI_API_KEY`" case no longer
  requires the value to touch the chat, the transcript, the project tree, or the
  agent's tool responses. The agent still does all the configuration work. The
  request/poll protocol removes the 120 s timeout from a flow that routinely
  takes minutes.
- **Positive (research).** A new audit event, `write_only_denied`, gives a
  measurable signal: a cooperating agent should never produce it. A canary test
  makes the property falsifiable over the channels it observes (spec §8.6; see
  the canary limit below).
- **Negative.** A same-user agent holding the agent's explicit credentials can
  run `sovereign-vault run -- printenv` or call `vault.resolve_env` directly.
  The `identity_required` refusal covers the identity-free default pairing, but
  the click prompt shows caller-supplied argv, so a careless approval still
  leaks the value. This is consistent with `docs/threat-model.md` §3.B (the
  pairing secret is available to any same-user process) and is declared, not
  solved, in the MVP.
- **Negative.** The child's injected environment is readable by same-user
  processes wherever the OS permits it — `/proc/<pid>/environ` on Linux,
  `ps -E` on macOS/BSD — for as long as the child lives; the boundary the
  injection provides is the process, not the operating system.
- **Negative.** argv and cwd are unattested caller input. The agent wires `run`
  into `package.json` or a script it can edit afterwards, so a click on a
  familiar-looking argv can execute something else, and the approval leaks the
  value.
- **Negative.** A child application that logs its own environment leaks the
  value to whoever reads its output. That is outside the vault's control.
- **Negative.** Keys already stored as plaintext `.env` entries keep their
  current exposure: `run` does not inject them, no guard protects them
  retroactively, and they remain readable through `vault.read` until the
  phase-2 migration of `clients/*`.
- **Negative.** The existing `clients/*` loaders read through `vault.read` and
  therefore cannot see `*.env-secret` until they migrate to `resolve_env`
  (phase 2).
- **Negative.** The value is unrecoverable from the vault UI by design. A lost
  key is regenerated at its provider.
- **Negative.** The canary test (spec §8.6) covers the channels it can observe:
  MCP responses, `audit.jsonl`, `run`/`mcp-stdio` stdout/stderr, app logs, and
  argv. A pass shows the value did not leave through those channels in that
  run; it does not prove the value never leaves.
- **Mitigation.** The resolve prompt always shows the full argv and cwd, and
  every resolve requires that click; `run` refuses identity-free pairing with
  `identity_required`; the audit log records every resolve.

## Alternatives considered

- **Desktop-only entry, no new tool.** The user adds keys in the app and the
  agent discovers them with `vault.list`. Rejected: the agent cannot ask for a
  key mid-task, so the user has to guess names and containers, and the
  interaction the user asked for disappears.
- **Keys as a new keyring object type, like broker secrets.** A cleaner model
  (per-key metadata, rotation), but it adds a storage type and bypasses the
  container `.env` convention the loaders already use. Deferred as a possible
  v2.
- **SV writes the value into the project file on disk.** Works with any
  application, but leaves plaintext in the project tree, which is the problem
  being solved. Rejected.
- **Broker-only consumption.** The key never leaves the vault, but it serves
  only outbound HTTP calls, not SDKs that read the environment. Rejected as the
  default; the broker remains available for that case.
- **Reuse the 120 s click-approval channel for entry.** Rejected: observed to
  expire before a human can fetch a key.
- **A "remember for 8 h" resolve grant keyed by `sha256(argv, cwd, container)`,
  in memory only and dropped on lock.** Would spare a click when the same
  command is launched again, but `npm run dev` is indirect argv, the agent
  edits the scripts that argv resolves through, and nothing attests which
  executable will actually run. Deferred until the resolve path can attest the
  executable it launches; the MVP resolves once per invocation, so the click
  cost is low.
- **Inject the container's `.env` entries alongside `*.env-secret`.**
  Compatibility with what users already store, but precedence between the two
  sources would be ambiguous, an agent could shadow the entered key by writing
  a same-named entry into `.env` (a file it can write today), and it would
  widen the set of values a single click releases. Rejected; `.env` remains a
  legacy source for the `vault.read` path only.
- **A separate runtime identity with its own token for `run`.** Would narrow the
  hostile-agent gap, but needs token custody outside the agent's reach, which
  the same-user boundary (threat model §3.B) cannot guarantee. Deferred until
  that boundary changes.
- **Let `run` pair as the Default agent.** Zero configuration for the user, but
  the Default agent is deliberately unscoped, so an identity-free process would
  hold the full tool surface behind a single human gate. Rejected; `run`
  requires an explicit agent identity and is refused with `identity_required`
  otherwise.

## References

- [ADR-0008](0008-per-agent-identity.md): per-agent identity and scopes; the
  three new actions are scope actions.
- [ADR-0009](0009-broker-and-transit-tools.md): use-without-exposure, extended
  here to process environments.
- [ADR-0014](0014-os-notifications-for-consent-prompts.md): OS notification on
  a pending request.
- [ADR-0021](0021-locked-state-wake-endpoint.md): Proposed and not implemented;
  only the unlocked-state wake queue exists today, with no CLI client. The MVP
  exits with code 75; waking a locked vault from `run` depends on that ADR.
- [ADR-0022](0022-tray-approval-menu.md): why the entry request is not mirrored
  into the tray.
- `docs/threat-model.md` §3.A–B.
