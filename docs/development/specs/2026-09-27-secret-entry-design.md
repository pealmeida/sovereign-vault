# Secret entry: agent-requested keys, desktop entry, runtime injection

- **Status:** Approved (ADR-0024 Accepted)
- **Date:** 2026-09-27
- **Decision record:** [ADR-0024](../../adr/0024-agent-requested-secret-entry.md)
- **Scope:** MVP

## 1. Problem

Getting a credential into a project today means one of three things: the user
pastes it into a `.env` or config file, the user pastes it into the agent chat,
or the user writes it into the vault through `vault.write` (which an agent can
later `vault.read`). The first leaves plaintext on disk and in git history, the
second puts the value in the model context and the transcript, and the third
still hands the value to the agent on read-back.

The user wants to type the key **into Sovereign Vault itself**, while the agent
does the configuration work (scripts, code, docs) **without ever receiving the
value**.

## 2. Goals and success criteria

**Goals**

1. An agent can ask for a named key mid-task; the vault shows a desktop modal
   pre-filled with that request; the user pastes the value there.
2. The user can also add a key from the desktop with no agent involved.
3. The project obtains the key at runtime through `sovereign-vault run`, which
   injects it into the child process environment only.
4. No agent operation returns the value.

**Success criteria**

- The canary test (§8.6) finds the value nowhere except in the child process
  environment: not in any MCP response, the audit log, `run`/`mcp-stdio`
  stdout/stderr, app logs, or process argv. The claim has a declared border:
  the canary proves the observed channels, not that the value *never* leaves —
  renderer memory, IPC payloads, `run`'s own buffers, and the environment of
  the child and its descendants are outside what the check can see.
- A cooperating agent completes the full flow (request → user enters → configure
  project → `npm run dev` works) without the value entering its context.

## 3. Threat model for this feature

The MVP targets a **cooperating but leaky agent**: an agent that follows its
instructions but whose context, transcript, logs, and commits must never
contain the secret by accident.

| Vector | Covered | How |
|---|---|---|
| Key pasted into chat or transcript | Yes | The flow never asks for it there |
| Key in a committed `.env` or config file | Yes | Never written to the project; `.env.example` holds names only |
| Agent reads the key via `vault.read` | Yes, **even for a hostile agent** | `secret_file_guard` (§5.1) |
| Agent overwrites, deletes, or destroys the key via MCP | Yes, even for a hostile agent | `secret_file_guard` (§5.1); it also denies `vault.destroy` on any container holding `*.env-secret`, in every mode |
| Key visible in argv | Yes | Injection through the environment only; values never reach the command line |
| Child environment readable by same-user processes (Linux `/proc/<pid>/environ`; macOS/BSD `ps e` — OS- and permission-dependent, but available to the account's own processes) | **No (declared)** | The same-user boundary (threat model §3.B); nothing at this layer hides a process's environment from its owner |
| Phishing through agent-supplied modal text | Mitigated | `purpose` rendered as plain text; `hint_url` domain shown prominently |
| Agent changes the approved command's script (e.g. `package.json`) before the user clicks | **No (declared)** | `argv` and `cwd` are caller-supplied and unattested; the prompt shows what will run, not what it does |
| Agent with a shell runs `sovereign-vault run -- printenv` or calls `vault.resolve_env` directly | **No (declared)** | Every resolve requires a click showing the exact argv; a malicious agent is out of MVP scope |
| `run` without an explicit agent identity pairs as the Default agent | Yes | Resolve requires an explicit identity; pairing-secret-only `run` is refused with `identity_required` (§5.2, §7.2) |
| Child application logs its own environment | **No (declared)** | Application responsibility; documented |

This is consistent with `docs/threat-model.md` §3.B: any same-user local process
can fetch the pairing secret while the vault is unlocked.

## 4. MCP surface

### 4.1 `vault.request_secret`

New `AccessAction::RequestSecret`.

**Input**

```json
{
  "container": "env-myapp",
  "env_var": "OPENAI_API_KEY",
  "purpose": "Configure the OpenAI client in src/llm.ts",
  "hint_url": "https://platform.openai.com/api-keys"
}
```

- `env_var` must match `^[A-Z][A-Z0-9_]{0,116}$`, else `invalid_env_var`.
  The bound is 117 characters: storage caps a logical file name at 128
  (`is_valid_file_name` in `sv-storage`), and the `.env-secret` suffix takes 11.
- `purpose` is required, 1–280 characters, stored and displayed as plain text.
- `hint_url` is optional and must be `https://`, else `invalid_hint_url`.
- The scope check (§5.2) runs **before** container existence and mode: a
  request for a container outside the agent's scopes is a scope denial, never
  `container_not_found`. The call must not probe containers the agent cannot
  touch.
- The container must exist, else `container_not_found`. The request records
  the container's generation id (§4.3) at creation.
- The container mode must be `DIRECT` or `APPROVAL`, else `unsupported_mode`.
  OTP containers are excluded because `run` has no channel to relay a code
  (§7.2); `ANONYMIZED`, `ZKP`, and `NATIVE` have no meaning for injected
  environment values.
- At most **3 pending requests per agent**; the fourth distinct request is
  refused with `too_many_requests`. A reused identical request (below) does
  not consume a slot. A **global cap of 10 pending requests** applies on top:
  when the vault is saturated, even an agent with spare slots gets
  `too_many_requests`.
- **No separate approval prompt.** The entry modal is the consent.

**Output (immediate)**

```json
{ "request_id": "sr_…", "status": "pending", "expires_at": "2026-09-27T21:15:00Z" }
```

- A request lives for **15 minutes**. The 120 s approval timeout was observed to
  be too short in practice; fetching a key from a provider dashboard takes
  minutes.
- An identical pending request (same agent, container, `env_var`) is reused:
  the call returns the existing `request_id` with `"reused": true` and does not
  open a second modal. This is a normal response, not an error.

### 4.2 `vault.secret_status`

New `AccessAction::SecretStatus`. No prompt.

**Input:** `{ "request_id": "sr_…", "wait_s": 30 }`. `wait_s` is optional,
0–30, and long-polls so the agent does not hammer the tool. At most **one
long-poll is active per `request_id`**: a second concurrent poll gets the
current status immediately, without waiting.

**Output**

| `status` | Extra fields |
|---|---|
| `pending` | `expires_at` |
| `stored` | `container`, `env_var`, `fingerprint`, `length`, `replaced`, `revision` |
| `cancelled` | — |
| `expired` | — |

- `fingerprint`: first 8 hex characters of
  `HMAC-SHA256(derive_subkey(DEK, b"sv/secret-fingerprint/v1"), value)`. It is
  keyed, so it is not computable offline without the key, but it is not a
  claim of zero leakage: it reveals **equality of two values stored under the
  same DEK**, and 32 bits can collide. Treat it as a visual confirmation that
  the user and the agent mean the same key, not as an identifier. A DEK
  rotation changes fingerprints; that is acceptable. Precisely because it is
  weak as an identifier, it is **presentation only**: consent and versioned
  writes bind the secret's `revision` (§4.3), never the fingerprint.
- `replaced`: `true` when the entry overwrote an existing key (rotation).
- Only the agent that created the request may query it; anyone else gets
  `unknown_request`.

**Request lifecycle**

- `cancelled` and `expired` are **statuses**, not errors: they appear in
  `secret_status` output (§8.1). Expected agent behavior is to ask the user
  and not loop.
- A submit that arrives after refusal or expiry is rejected; the request is
  already terminal.
- Locking the vault cancels every pending request (status `cancelled`, reason
  `vault_locked`) and closes any open entry modal.
- Requests live in desktop process memory only. A desktop restart loses them:
  every subsequent poll returns `unknown_request`.
- Terminal states are retained for 15 minutes after they are reached, so a
  slow-polling agent still learns the outcome; after that the request is
  pruned and becomes `unknown_request`.
- Submit, cancel, and expiry are serialized per request; the first transition
  wins.
- Submit revalidates the requesting agent's scope, the container's mode, and
  the container's **generation id** (§4.3) — a recreated namesake is refused,
  not silently reused — and then writes the key as a per-key
  compare-and-swap on `revision` (§6). Revalidation and the write happen
  under the container's lock, so no destroy or rotation can interleave
  between check and commit.

### 4.3 Storage

Each key is a separate file `<ENV_VAR>.env-secret` in the container, holding the
raw value, encrypted like any other container file. One file per key keeps
rotation, fingerprinting, and removal independent, with no read-modify-write of
a shared `.env`.

Two versioning primitives back the safety rules elsewhere:

- **`revision`**: a counter monotonic **per container and per generation**,
  kept in the container's metadata — never in the key file, which cannot see
  its siblings. It is incremented on every write of any key in the container,
  and a revision is **never reused within a generation**: deleting a key and
  storing it again yields a revision strictly greater than any previous one
  of that generation. Each `*.env-secret` records the revision it was
  written with. That counter is the compare-and-swap token: consent binds
  (name, revision) pairs (§7.2) and submits carry the revision the user saw
  (§6). The fingerprint is not a concurrency control; the revision is.
- **Container generation id**: each container carries an immutable identifier
  minted at creation. Destroying and recreating a container under the same
  name yields a new id, so a request or a consent that names a container can
  tell it from its namesake. Requests record the generation id at creation;
  submit and resolve revalidate against it (§4.2 lifecycle, §7.2).

### 4.4 Command pack

`integrations/agents/sovereign-vault.commands.yaml` gains:

- `/sovereign-vault request key <ENV_VAR> --vault <container> --purpose "<text>" [--hint-url <url>]`
- `/sovereign-vault key status <request_id>`

Plus a behavior note: after a key is stored, configure the project to use
`sovereign-vault run`, create `.env.example` with names only, and never attempt
to read `*.env-secret`.

## 5. Security boundary

### 5.1 `secret_file_guard`

A single guard in `sv-mcp`, evaluated in `call_tool`, enforces two checks.
They are deliberately different in what they look at and where they sit
relative to scoping:

- **Name guard** — `ReadFile`, `WriteFile`, `DeleteFile`. Purely syntactic:
  normalizes `file_name` (case-fold, strip trailing whitespace and dots) and
  denies with `write_only_secret` when it ends in `.env-secret`. Runs
  **before** `enforce_scopes` and the mode flow, in every mode including
  `DIRECT`; it never inspects content.
- **Destroy check** — `DestroyContainer`. Content-dependent, so the order
  inverts: `enforce_scopes` runs **first**. An agent out of scope for the
  container gets the ordinary scope denial whether or not it holds secrets —
  the guard must not become an oracle by which an out-of-scope agent learns
  which containers hold keys. Only an in-scope agent reaches the scan: `vault.destroy` on a container that holds any `*.env-secret` is
  denied with `write_only_secret` in **every** mode, `DIRECT` included, and
  such containers are destroyed only from the desktop. The scan for
  `*.env-secret` and the removal run atomically under the same
  container/manifest lock, so a secret written between check and removal
  cannot be silently deleted.
- Both are hard rules, not configuration.
- MCP `vault.list` keeps returning only `name` and `mode` — no size, as
  today. The desktop list may show size, but the displayed secret length
  comes from stored metadata, never from the encrypted blob size.
- `sv-storage::list_files` revalidates on-disk names against
  `is_valid_file_name` and skips what fails, so a planted decoy file whose
  name survives neither validation nor the guard cannot be listed as if it
  were a real entry.

The desktop guard is enforced in the **backend**, not only in the viewer: the
Tauri commands `vault_read_file` and `vault_export_file` refuse
`*.env-secret` at the command level, because both return or decrypt content
and the renderer can invoke them directly. The file viewer shows name,
fingerprint, and the recorded plaintext length, and offers only "Replace"
(reopens the entry modal) and "Delete". Nobody reads the value back through
the UI. The only egress is `resolve_env`. A lost key is regenerated at
the provider.

### 5.2 Per-agent scopes (ADR-0008)

`RequestSecret`, `SecretStatus`, and the new `ResolveEnv` are scope actions,
matched against `container_glob` like file actions. An agent scoped to
`env-myapp/*` can only request keys for `env-myapp`.

`ResolveEnv` requires an **explicit agent identity** (`SV_AGENT_ID` plus the
pairing token): `run` that pairs with the pairing secret alone is the
unscoped Default agent and is refused with `identity_required`. An explicit
identity still needs `ResolveEnv` on the container's glob. Declared
residual: a same-user process holding those credentials can still resolve —
the same-user boundary (threat model §3.B) is not closed by this.

### 5.3 Audit

New `AuditAction` variants. Container names follow the existing HMAC-hashing
rule. No values are ever recorded. Where a non-secret string must be recorded
and later checked, it uses the same domain-separated HMAC under an audit
subkey — never a bare `sha256`, which an attacker with the log could
brute-force offline.

| Event | Fields |
|---|---|
| `secret_requested` | agent_id, container, env_var, request_id |
| `secret_stored` | request_id or `desktop`, container, env_var, fingerprint, length, replaced |
| `secret_request_cancelled` | request_id, reason (`refused \| vault_locked \| closed`) |
| `secret_request_expired` | request_id |
| `resolve_env` | agent_id, container, variable names and revisions, `consent_id`, HMAC-bound argv and cwd, `granted_by: click` |
| `write_only_denied` | agent_id, action, container, file_name |

`write_only_denied` doubles as a research signal: a cooperating agent should
never trigger it.

## 6. Desktop entry modal

New component `ui/src/components/SecretEntryModal.svelte`, using the
`modal-shell` / `panel-card` pattern of `ApprovalModal.svelte`.

**Entry points**

1. **Agent request:** new event `vault://secret-request` carrying
   `{ request_id, agent, container, env_var, purpose, hint_url, expires_at }`.
   Container and `env_var` are **locked**; the user confirms or refuses exactly
   what the agent asked for.
2. **"New key" button** on a container view: container preselected, `env_var`
   editable with the same validation.

**Layout**

```
┌ Key request · agent: claude-code ──────────────────┐
│ OPENAI_API_KEY  →  env-myapp                       │
│ "Configure the OpenAI client in src/llm.ts"        │  purpose, plain text
│ Get the key: platform.openai.com ↗                 │  hint_url, if present
│ [ ••••••••••••••••••••  ] [reveal]                 │  masked, no autocomplete
│ ⚠ Key exists (revision 7 will be replaced)         │  rotation only
│ Expires in 14:32                                   │
│                          [Refuse]  [Store]         │
└────────────────────────────────────────────────────┘
```

**Behavior**

- Input: `type=password`, `autocomplete=off`, no autocapitalize, no
  spellcheck, a reveal toggle.
- Leading and trailing whitespace and newlines are trimmed (a common paste
  error). An empty value is refused. If the trim changed the pasted text, the
  modal says so and the value is stored only after the user confirms again.
- NUL bytes are refused, the max size is **16 KiB** after trim, and trim is
  applied in the **backend**: both Tauri commands (`submit_secret`,
  `submit_secret_direct`) enforce these rules and `resolve_env` re-applies
  them when loading a value for injection, failing the resolve if a stored
  file violates them. The modal mirrors the same rules for immediate
  feedback, but a UI that misses them cannot push a bad value past the
  commands.
- `purpose` is rendered as plain text, never HTML. `hint_url` opens only on
  click, through the opener plugin, with its domain shown.
- A visible countdown to `expires_at`.
- A click-approval arriving while this modal is open is shown **on top of**
  it: its 120 s timeout must not expire behind a 15-minute entry modal. The
  entry modal keeps its state — a typed value is preserved and the countdown
  keeps running — and the entry modal returns to the front when the approval
  is resolved.
- Refuse, close, or expiry resolves the request as `cancelled` / `expired`.

**Value path**

- "Store" calls a new Tauri command
  `submit_secret(request_id, value, expected_revision)` —
  `expected_revision` is the revision currently displayed for that key, or
  `null` for a new one. `submit_secret` inherits the container generation id
  recorded when the request was created (§4.3): the request's target is the
  container instance, not its name. For the desktop-initiated path there is
  no request to inherit from, so `submit_secret_direct(container, env_var,
  value, expected_revision, expected_generation)` carries the generation id
  the modal displayed when it opened. Without it, a modal left open on an
  empty container that was destroyed and recreated under the same name would
  send `expected_revision=null` into the new instance and silently "create"
  over a generation the user never saw.
- Rust holds the value in `Zeroizing<String>`, keeps it out of `Debug`,
  writes `<ENV_VAR>.env-secret` through the existing file-write path under
  the container lock: `expected_generation` is compared first, then a per-key
  compare-and-swap on `expected_revision` (§4.3). `submit_secret` runs the
  same comparison against the request's recorded generation id. On a
  generation or CAS miss nothing is written: the backend answers
  `secret_changed`, the modal reopens with the current state (current
  container generation, current `revision`, new `replaced` warning), and only
  a fresh human confirmation can overwrite. On a successful write the pending
  request resolves as `stored` and the command returns
  `{ fingerprint, length, replaced, revision }`.
- The front end clears the component state immediately after submit. The value
  never passes through a store, toast, or log.

**Tray:** the request is **not** mirrored into the tray menu (no input there).
Only the OS notification "An agent requested a key" fires, reusing
`notify_once`.

## 7. `sovereign-vault run` and `vault.resolve_env`

### 7.1 CLI

```bash
sovereign-vault run --container env-myapp [--only OPENAI_API_KEY ...] [--override] -- npm run dev
```

The agent wires this into the project, typically
`"dev": "sovereign-vault run -c env-myapp -- next dev"` in `package.json`, and
adds `.env.example` with variable names only plus a README note.

### 7.2 Protocol

- `run` pairs with the gateway exactly like `mcp-stdio` and sends the internal
  JSON-RPC method `vault.resolve_env`
  `{ container, only?, argv, cwd }`.
- `vault.resolve_env` is **not listed in `tools/list`**. A cooperating agent has
  no reason to call it; one that does hits the same prompt (declared limit,
  §3).
- **Always a click**, even for a `DIRECT` container. There is **no
  "remember" grant in the MVP**: `argv` and `cwd` are supplied by the caller
  and are never attested — the same `npm run dev` can execute a `package.json`
  the agent edited minutes later — so a time-boxed grant would punch a hole
  through the one gate that still means something. The cost is low: `run`
  resolves once per invocation, and `nodemon` / `next dev` restarts happen
  inside the child, which needs no second resolve. Containers in any mode
  other than `DIRECT` or `APPROVAL` are refused with `unsupported_mode`.
  The prompt shows the exact argv, cwd, container, and for every variable its
  **name and `revision`** (the fingerprint may accompany it as a
  human-readable hint, but is not what is approved). Never values.
- The consent binds the set of (name, revision) pairs shown: if a key is
  rotated between the prompt and the consumption, the revision moves, the
  resolve fails, and the command must be approved again. A fingerprint
  collision cannot defeat this because the bound token is the counter, not
  the 32-bit digest (§4.2). Delete-and-recreate defeats nothing either:
  revisions are never reused within a generation (§4.3), so the recreated
  key's revision is strictly greater than the consented one.
- Revalidation happens **after** the click, before any value is returned: the
  caller's identity, its scope on the container, the container's mode, and
  the container's **generation id** against the one the consent captured
  (§4.3), and the current `revision` of each key against the consented
  pairs. Revalidation and the reads that produce the values happen under the
  same container lock, so nothing can rotate between check and hand-off. Any
  divergence fails the resolve — `secret_changed` for a moved revision —
  with no values returned: the click approves a state, not a blank cheque on
  what follows.
- `run` pairs with an **explicit agent identity** (§5.2); pairing-secret-only
  `run` is refused with `identity_required`.
- The response returns values only to the `run` process over the loopback
  socket.

### 7.3 Injection

- Source: **only** the container's `*.env-secret` files. The container's
  `.env` file is **not** a source in the MVP: it is ordinary vault content
  that a scoped agent can still read and write through `vault.read`, and
  merging it into the injection path would widen what a resolve click
  releases. Legacy secrets kept in a container `.env` remain readable by the
  `clients/*` loaders through `vault.read` until those migrate to
  `resolve_env` (phase 2); they get no retroactive protection, and this is
  documented as such.
- A variable already present in the environment is **not overridden** without
  `--override`; `run` warns on stderr with the variable name only.
- Unix: `run` builds the child environment and calls `exec()`, so the command
  replaces it and signals and exit codes behave natively. Windows: spawn, wait,
  and propagate the exit code.
- `run` never prints values, never writes to disk, never passes values through
  argv.

### 7.4 Locked vault

`run` exits with code 75 (`EX_TEMPFAIL`) and the message "unlock Sovereign
Vault". ADR-0021 is **Proposed and not implemented**: the artifact has only a
wake prompt queue while the vault is unlocked, no locked-state wake endpoint,
and no CLI client. Waking a locked vault from `run` is phase 2, conditional
on ADR-0021 being implemented first.

## 8. Errors and tests

### 8.1 Error codes

Returned as `isError` with text `code: message`, the same pattern as
`otp_required`.

| Code | When | Expected agent behavior |
|---|---|---|
| `invalid_env_var` / `invalid_hint_url` | Input validation fails | Fix and resend |
| `container_not_found` | Container does not exist (and is in scope) | Ask the user to create it |
| `unsupported_mode` | Container is not `DIRECT` or `APPROVAL` | Ask the user for an `APPROVAL` container |
| `too_many_requests` | Agent has 3 pending, or the vault has hit the global cap of 10 | Wait; poll existing requests |
| `identity_required` | `run`/`resolve_env` without an explicit agent identity | Ask to be paired with an explicit identity |
| `unknown_request` | Unknown id or another agent's id | — |
| `secret_changed` | Compare-and-swap miss: the key's `revision` moved since the value shown was computed (submit §6, resolve §7.2) | Re-read the current revision; ask the user to re-confirm; never blind-retry the write |
| `write_only_secret` | Read, write, or delete of `*.env-secret`, or `vault.destroy` of a container holding one | Use `run`; never work around it |
| `vault_locked` | Vault locked | Ask the user to unlock; `run` exits 75 |

Refused and expired requests are **not** errors here: `cancelled` and
`expired` are `secret_status` values (§4.2, Request lifecycle).

### 8.2 Unit tests (`sv-mcp`)

- `secret_file_guard`, including bypass attempts: case, trailing whitespace and
  dots, `../` segments.
- Destroy regression: `vault.destroy` of a container holding a `*.env-secret`
  is denied with `write_only_secret` even in `DIRECT` mode; destroying a
  container with no secrets still works. Ordering: an agent **out of scope**
  for the container gets the scope denial, never `write_only_secret`, so the
  denial cannot disclose that the container holds keys (§5.1). Race case: a
  desktop `submit_secret`/`submit_secret_direct` racing an in-flight destroy
  resolves on the container lock — either the write lands before the scan
  (destroy denied) or after it (the submit sees the generation id changed
  and fails); no interleaving deletes a stored secret. `WriteFile` cannot
  reach this race: the name guard denies it before the mode flow.
- `env_var` and `hint_url` validation, including the length boundary: 117
  characters accepted, 118 rejected.
- Scope-before-existence: an out-of-scope container yields the scope denial,
  not `container_not_found`.
- Pending-request dedupe and the pending cap: the 4th distinct request gets
  `too_many_requests`; a reused request does not consume a slot.
- `enforce_scopes` for `RequestSecret`, `SecretStatus`, `ResolveEnv`.
- `identity_required`: `resolve_env` under the Default (pairing-secret-only)
  identity is refused.
- State transitions `pending → stored | cancelled | expired`, and that only the
  requesting agent can read status. Lifecycle: locking the vault cancels
  pending requests with reason `vault_locked`; a late submit is rejected; the
  first terminal transition wins; after the 15-minute retention a terminal
  request reads as `unknown_request`; a desktop restart erases requests.
- Rotation between consent and consumption: if the `revision` behind a
  consented (name, revision) pair moves, the resolve fails with
  `secret_changed` and no values are returned.
- Compare-and-swap on entry: a submit carrying a stale `expected_revision`
  (or `null` against an existing key) is refused with `secret_changed` and
  the stored value is untouched; a submit carrying the current revision
  succeeds and bumps it.
- Generation id: destroy + recreate of a container under the same name
  changes the id; a pending request or a stored consent bound to the old id
  fails revalidation instead of silently applying to the new container.
  Case (a): destroy and recreate an **empty** container while a
  desktop-initiated modal is open — `submit_secret_direct`'s
  `expected_generation` mismatches, `secret_changed`, nothing is written;
  the same case through `submit_secret` fails on the request's recorded id.
- Revision never reused within a generation: case (b) — delete a key, store
  a different one, then land a pending submit carrying the old
  `expected_revision`: refused with `secret_changed`, because the container
  counter moved past it (§4.3). Case (c) — delete and recreate a key between
  the resolve click and consumption: revalidation sees a strictly greater
  revision than the consented pair and the resolve fails with no values
  returned.
- `unsupported_mode` for OTP and `ANONYMIZED` containers on both
  `request_secret` and `resolve_env`.

### 8.3 Unit tests (desktop)

`submit_secret` writes `<ENV_VAR>.env-secret`, sets `replaced` on rotation,
bumps `revision`, produces a stable fingerprint for the same value and DEK,
and enforces NUL/16 KiB/trim in the command itself — a value pushed straight
through the Tauri API, bypassing the modal, cannot exceed them.
`vault_read_file` and `vault_export_file` refuse `*.env-secret` at the command
level — the guard is in the Rust backend, not only in the viewer.

### 8.4 Integration (`crates/sv-core/tests/mcp_e2e.rs`)

`request_secret → submit (simulated) → secret_status stored → resolve_env`,
then `vault.read` of the same key is denied with `write_only_secret`. The
resolve leg pairs with an explicit identity (§5.2); a second leg with the
Default identity asserts `identity_required`.

### 8.5 UI (vitest)

`SecretEntryModal`: masked input, trim, empty value refused, `purpose` with
HTML is rendered as text, countdown, state cleared after submit. Approval
stacking: an approval prompt rendered over the open modal does not clear the
typed value, the countdown keeps running behind it, and the entry modal is
restored once the approval is resolved. On `secret_changed` the modal reopens
showing the current `revision` state, and the stored NUL/16 KiB rules it
mirrors match the backend's.

### 8.6 Canary test (central property)

The live e2e stores `SV_CANARY_<uuid>` through the full flow, then searches for
the value in every MCP response, `audit.jsonl`, `run` and `mcp-stdio`
stdout/stderr, app logs, and process argv. **Any occurrence fails the test.**
The only permitted egress is the child environment, checked by a child that
compares a hash.

### 8.7 CLI

`run` injects into the child, respects `--override`, propagates the exit code,
and exits 75 on a locked vault.

### 8.8 Manual

`docs/testing/` gains the case "request key → paste in modal → `npm run dev`
works".

## 9. Phases

- **MVP:** everything above.
- **Phase 2 (out of scope here):** migrate `clients/*` loaders from `vault.read`
  to `resolve_env` (today they cannot see `*.env-secret`), and only then
  consider accepting the container's `.env` as a `run` source (§7.3); a
  "remember" resolve grant, which first requires attestation of the executed
  binary — raw `argv`/`cwd` can be re-approved by an edited script and is not
  a trustworthy grant key; a CLI client for the ADR-0021 wake endpoint so
  `run` can wake a locked vault, conditional on ADR-0021 being implemented
  (it is Proposed; the endpoint does not exist in the artifact); OTP
  containers for `run` (a terminal code prompt); glob support in `--only`;
  agent-initiated rotation.

## 10. Documentation to update with the implementation

- `docs/threat-model.md`: the §3 table rows, including the new declared
  limits — the child environment is visible to same-user processes
  (`ps e`, `/proc/<pid>/environ`), and the approved command's script can be
  changed before the click — alongside the existing ones.
- `docs/USAGE_REAL.md`: a "Request a key instead of pasting it" section.
- `docs/testing/mcp-test-cases.md`: the new tools and error codes.
- `README.md`: tool count and a line under "What's implemented".
