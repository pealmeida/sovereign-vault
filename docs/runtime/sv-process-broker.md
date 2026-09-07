# `sv-process-broker` Specification

## 1. Responsibility

`sv-process-broker` executes typed, registered application actions while
keeping secret material out of model context and ordinary client configuration.
It is not a shell service. The model chooses a profile and validated parameters;
the broker chooses the executable, fixed arguments, environment, secret
delivery method, working directory, limits, and destination controls.

## 2. Profile identity

A profile contains:

- stable ID, operator label, version, enabled state;
- absolute executable path;
- executable identity policy: pinned SHA-256, trusted publisher, package
  identity, or explicit weaker path-only mode;
- fixed arguments and a JSON Schema for typed variable parameters;
- allowed working-directory roots;
- environment allowlist and fixed safe variables;
- secret injection declarations;
- network destination policy where enforceable through brokered I/O;
- child-process policy;
- stdin/stdout/stderr mode and byte limits;
- wall/idle timeouts, concurrency, and termination policy;
- input/output sanitizer policy;
- consent requirement and audit labels.

Changing executable identity, arguments, schema, injection, destination, or
limits changes the profile digest and invalidates existing consents.

## 3. Invocation API

Conceptual request:

```json
{
  "profile": "deploy-production",
  "parameters": {
    "project": "website",
    "environment": "production"
  },
  "references": {
    "credential": "svref:v1:…"
  },
  "working_directory": "D:/Code/approved-projects/website"
}
```

The request contains no executable path, command string, arbitrary arguments,
environment map, or secret value.

## 4. Validation and execution order

1. Authenticate principal and load immutable profile version.
2. Check principal scope for profile and action.
3. Validate typed parameters with depth/count/string limits.
4. Resolve and canonicalize working directory; enforce allowed roots and
   symlink/reparse-point containment.
5. Verify executable identity immediately before start.
6. Resolve reference metadata and enforce profile slot, class, audience,
   destination, expiry, and use limits.
7. Build exact operation descriptor and obtain bound consent.
8. Append audit intent.
9. Obtain short-lived material-use leases and inject secrets.
10. Start process without shell interpretation.
11. Enforce time, output, input, child, and cancellation limits.
12. Filter output and secret echoes.
13. Append outcome audit and release sanitized result.

## 5. Secret injection methods

Ordered from preferred to compatibility fallback:

### 5.1 Brokered protocol operation

The application does not receive the secret. It calls or is called through a
local broker that adds authentication to an allowed network request. This gives
the strongest use-without-disclosure property and reuses ADR-0009.

### 5.2 Inherited anonymous pipe / dedicated stdin protocol

Secret bytes are written after process start to a dedicated pipe or documented
stdin JSON field. They do not appear in argv, environment, or disk. The target
process still receives plaintext and must be trusted for that credential.

### 5.3 Named pipe or local socket callback

The broker creates a one-shot, access-controlled endpoint bound to the process
identity where the platform permits. It expires after one retrieval. Same-user
malware remains in the broader out-of-scope boundary.

### 5.4 Environment variable — weaker compatibility mode

Allowed only per profile and secret slot. The broker constructs a minimal
environment, starts the process, and zeroizes its own temporary values where
possible. The child and descendants can read the environment, and OS/process
inspection may expose it; documentation and consent must label this limitation.

### 5.5 Temporary file — disabled by default

Permitted only for applications that cannot consume another method and only
with explicit operator configuration. Requirements: dedicated directory,
exclusive creation, restrictive ACL/mode, no predictable name, no project-tree
location, best-effort deletion on every exit path, startup cleanup, and an
audit flag identifying disk materialization. Deletion is not proof that storage
media or backups contain no recoverable copy.

Secrets never appear in command-line arguments.

## 6. Process creation

- Windows uses direct `CreateProcess` semantics through safe Rust libraries,
  with an explicit argument vector and hidden window unless interaction is part
  of the profile.
- Unix uses direct executable/argv spawning, never `/bin/sh -c`.
- PowerShell, `cmd.exe`, shells, interpreters, and package runners require their
  own tightly constrained profile; a script string supplied by the model is
  prohibited.
- The broker closes unrelated handles/file descriptors.
- The child receives only allowlisted environment variables.
- Interactive TTY profiles are deferred because screen/keyboard mediation is a
  separate security surface.

## 7. Filesystem and network limits

Working-directory containment is not a complete filesystem sandbox. Profiles
should use OS sandbox facilities when available, but the initial cross-platform
claim remains logical restriction only.

Network guarantees are strongest when the process uses brokered HTTP. A general
process with ambient network access may exfiltrate a secret it receives. Such a
profile must be labeled `secret-receiving-networked`, require stronger consent,
and cannot be described as non-exportable. Platform firewall/sandbox integration
is later work.

## 8. Output filtering

Stdout and stderr are separate bounded streams. The filter detects:

- exact secret echoes using keyed in-memory matchers without logging matches;
- encoded/common transformed echoes only where bounded detectors exist;
- configured PII categories;
- opaque reference tokens and internal IDs that should remain local;
- ANSI/control sequences and terminal escape injection;
- excessive lines/bytes and invalid UTF-8.

To catch boundary-split values, streaming output retains a capped suffix sized
to known secret/detector maxima. Binary output is not returned to a model in
version 1. A secret echo denies or redacts the affected output according to
policy and records only a count.

Filtering cannot prove that an application did not exfiltrate over its own
network connection or side channel.

## 9. Exit and cancellation semantics

Result includes safe exit category, duration, output counts, redaction counts,
and sanitized stdout/stderr. It does not automatically treat exit code zero as
policy success if output/audit failed.

Cancellation first closes secret delivery, then requests graceful termination,
then uses profile-defined forced termination after a deadline. Child-process
cleanup is platform-specific and tested. If external effects may have occurred,
the outcome says so.

## 10. Required profile classes

Initial implementation should cover representative patterns rather than a
general shell:

- provider HTTP call via broker;
- deploy CLI receiving a token through stdin;
- database client using a one-shot local socket or environment fallback;
- signing tool using a vault signing operation rather than private-key export;
- external MCP stdio server with no secret injection.

## 11. Acceptance criteria

- Model-controlled executable, shell, raw argv, env, and destination are
  impossible through the typed API.
- Secrets never appear in argv, audit, logs, safe errors, or sanitized output.
- Profile/executable/parameter mutation invalidates consent.
- Path traversal, symlink/reparse escape, child-process escape attempts,
  timeouts, oversized output, invalid UTF-8, control sequences, and secret
  echoes are covered by negative tests.
- Each injection method has an explicit threat/coverage test and UI label.
- No profile is described as OS-sandboxed without platform-specific evidence.

