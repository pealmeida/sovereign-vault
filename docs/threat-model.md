# Threat model — Sovereign Vault

Status: living document · early release (v0.1.0). This describes what Sovereign
Vault defends against, what it explicitly does **not**, and the residual risks
you accept by using it today.

## 1. What we protect

**Assets**
- Secret material at rest: container files (`.env`, API keys, notes), transit
  keys, signing private keys, brokered secrets.
- The key hierarchy: the OS-keychain/passphrase-wrapped Key-Encryption-Key (KEK)
  and the rotatable Data-Encryption-Key (DEK) it wraps.
- The recovery phrase (BIP39, 24 words).
- The integrity of the audit log.

**Security goals**
1. **Confidentiality at rest** — no plaintext secret is ever written to disk
   unencrypted by the vault.
2. **Least-privilege agent access** — an agent only reaches what its scoped
   token grants, and only after the configured human gate.
3. **Human-in-the-loop control** — protected operations require an explicit
   desktop Approve (or a cross-channel OTP) before they complete.
4. **Use-without-exposure** — transit `encrypt`/`decrypt`/`sign` and the broker
   let an agent *use* a key without ever receiving its bytes.
5. **Tamper-evidence** — security-sensitive operations are recorded in an
   HMAC-authenticated log and checkpoint; modification, deletion, or truncation
   causes verification to fail before an unlocked desktop session is accepted.

## 2. Trust boundaries

| Zone | Trust | Notes |
|---|---|---|
| The human at the desktop app | **Trusted** | Approves/denies, holds the passphrase/recovery phrase. The root of trust. |
| The local OS user account + OS keychain | **Trusted** | The KEK lives here (keychain custody) or is derived from the passphrase. |
| MCP agents / clients (Claude, Cursor, …) | **Untrusted** | Reach the vault only over the loopback MCP server, only when unlocked, only within their token's scope, only past the human gate. |
| Data at rest (vault root, backups) | **Untrusted medium** | Assumed readable by an attacker who steals the disk/backup. |
| Outbound network (broker targets) | **Untrusted** | Broker requests are constrained by an allowlist and SSRF guards. |

The MCP and HTTP servers bind to **loopback only** (`127.0.0.1:9944` / `:9943`)
and only while the vault is **unlocked**. Locking stops them.

## 3. Adversaries & mitigations

### A. A compromised or malicious MCP agent
The headline threat: an agent the user connected turns hostile or is hijacked.
- **Scoped identity** — each agent has its own token and capability scope; a
  scope can only *narrow* access, never widen a container's mode ceiling
  (`crates/sv-core`, ADR-0008).
- **Per-operation gating** — APPROVAL containers raise a desktop modal showing
  agent id, action, container, and file; OTP containers require a code shown on
  the desktop and re-sent by the agent (single-use, 120s TTL).
- **Use-without-exposure** — for transit/sign/broker, the agent receives a
  ciphertext/signature/response, never the key.
- **Audit** — every call is logged with the agent id.

### B. Another local process / local malware (vault unlocked)
- Loopback binding and browser-origin checks block remote and cross-origin web
  callers. However, `/.well-known/mcp-pairing` exposes the per-launch shared
  secret without authentication to support `mcp-stdio`, so an arbitrary local
  process can fetch it and pair while the vault is unlocked.
- Scoped agent tokens provide identity, least privilege, and revocation for
  configured agents; they do not turn the local same-user process boundary into
  an untrusted boundary.
- **Residual risk:** a process running as the same OS user with the vault
  unlocked is largely inside the trust boundary (it can read the keychain entry,
  scrape memory, or read a session-cached `.env`). Sovereign Vault does not
  defend a fully-compromised local account. Lock when away.

### C. Disk / backup theft (vault locked)
- All container file contents and secret key material are sealed with
  XChaCha20-Poly1305; keys are wrapped by a KEK derived via Argon2id
  (passphrase) or stored in the OS keychain. Without the
  passphrase/keychain/recovery phrase, the ciphertext is not recoverable.
- **Metadata is not confidential:** logical container/file names are visible in
  paths, modes and descriptions are plaintext in `manifest.json`, and encrypted
  blob sizes and filesystem timestamps remain visible.
- Audit log container/file names are **HMAC hashes**, not plaintext, so the log
  does not directly disclose those names. Other audit metadata (actions,
  outcomes, transport, mode, sizes, and timestamps) is authenticated but not
  encrypted.

### D. SSRF / exfiltration via the broker
- The broker is **off by default** (`SV_ENABLE_BROKER=1` to enable; the tool is
  absent from `tools/list` otherwise).
- When on: requests must match a host allowlist; private/loopback/link-local
  targets (v4+v6) are denied unless explicitly opted in; plain HTTP and
  disallowed methods are rejected; responses are size-capped; secret/auth
  headers are never returned to the agent (ADR-0009).

### E. Audit-log tampering
- Records and the durable checkpoint are HMAC-SHA256 authenticated and form one
  MAC chain across active and rotated segments. Desktop unlock opens and fully
  verifies this state; missing, edited, deleted, or truncated state fails closed.
- A checkpoint stored beside the log cannot distinguish a complete, internally
  consistent rollback of the entire audit directory. Rollback detection needs
  an external trusted anchor such as the OS keychain or a remote transparency
  service.

### F. Supply chain
- CI runs `cargo audit` (RUSTSEC) and `cargo deny` on every change and weekly;
  Dependabot proposes dependency updates. `#![forbid(unsafe_code)]` is enforced
  workspace-wide.

## 4. Explicit non-goals (out of scope today)

- **Multi-user / remote / networked** operation. Single OS user, single machine.
- **Defending a fully-compromised local account** with the vault unlocked
  (memory scraping, keylogging, ptrace).
- **Side-channel resistance** (timing, power, EM) beyond what the underlying
  crypto libraries provide.
- **Coercion / rubber-hose** resistance; no duress modes.
- **Anti-malware / OS hardening.** We assume a reasonably healthy host.
- The `ANONYMIZED` / `ZKP` / `NATIVE` modes are **reserved but not implemented**
  and are rejected at runtime — do not rely on them.

## 5. Residual risks & known gaps (track to closure)

- **Session cache** (`clients/*`, opt-in) writes *decrypted* secrets to a `0600`
  temp file for its TTL — partially defeats the vault. Off by default; documented.
- **Failed credential attempts** cannot enter the trusted audit stream because
  its authentication key is available only after successful credential or
  recovery verification. Host authentication telemetry is required to monitor
  those failures.
- **Bootstrap pre-key activity** cannot be authenticated until initial key
  establishment creates the audit identity key. The bootstrap audit intent is
  therefore recorded immediately after that key becomes available.
- **Metadata confidentiality** is not provided for logical path names, manifest
  modes/descriptions, ciphertext sizes, or filesystem timestamps.
- **Complete audit snapshot rollback** is not detectable without an external
  trusted checkpoint anchor.
- **Unsigned builds** (pre-1.0): no code-signing/notarization yet; verify your
  build provenance. Tracked for the first signed release.
- **No independent security audit** has been performed. Early release.

## 6. Reporting

Found a vulnerability? See [`SECURITY.md`](../SECURITY.md) — report privately via
GitHub Security Advisories, never a public issue.
