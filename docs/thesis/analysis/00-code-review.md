# Grounded code and design review — thesis revision

**Scope.** This review compares the proposal-stage paper (`docs/thesis/oliveira-2026-soberania-de-dados-agentes-ia.pdf`, §§1–3) with the working tree on 2026-08-02. “Supported” means the stated mechanism exists in the artifact, not that it proves a general security property. Source locations are intentionally primary evidence. Existing material was read and used as context: `docs/SECURITY-REVIEW.md`, `docs/threat-model.md`, `docs/thesis/{EVALUATION,TRACEABILITY,EVIDENCE-CAPTURE}.md`, and all ADRs. This report extends them; it does not repeat their test narrative.

**Severity.** Tier-1 blocking = revise before making the corresponding research/security claim; Tier-2 major = material scope/method qualification; Tier-3 minor = precision/reproducibility correction. The focused library test run completed successfully: 159 tests passed across `sv-storage`, `sv-privacy`, `sv-audit`, `sv-mcp`, and `sv-core`; `sv-mcp` emitted one unused-test-function warning. Passing tests do not cure the design limitations below.

## 1. Memory safety, Tauri, and the RQ3 isolation claim

### 1.1 Rust removes a large class in first-party code, but does not “eliminate” the class end-to-end

**Verdict: PARTIAL. Severity: Tier-2 major.**

The workspace lint forbids `unsafe_code` (`Cargo.toml:26-27`), and every workspace package inspected opts into workspace lints (for example `crates/sv-mcp/Cargo.toml:31-32`, `crates/sv-storage/Cargo.toml:21-22`, `apps/desktop/src-tauri/Cargo.toml:47-48`). The security-critical first-party crates also state `#![forbid(unsafe_code)]`, e.g. `sv-crypto` (`crates/sv-crypto/src/lib.rs:19`), `sv-mcp` (`crates/sv-mcp/src/lib.rs:18`), and desktop (`apps/desktop/src-tauri/src/lib.rs:13`). No first-party Rust `unsafe` block or `extern "C"` declaration was found by source search.

That property does **not** constrain dependency internals. The desktop explicitly depends on Tauri and plugins (`apps/desktop/src-tauri/Cargo.toml:25-27`), while key custody enables native Linux/Windows/macOS backends in `keyring` (`crates/sv-keychain/Cargo.toml:13`; `crates/sv-keychain/src/lib.rs:108-118`). The resolved dependency graph includes native/FFI system crates (`webkit2gtk-sys`, GTK/GDK/GLib `-sys`, `dbus-secret-service`, `libdbus-sys`, `ring`); they are outside the workspace lint. Therefore Rust materially reduces *memory-unsafe first-party implementation code*, but cannot prove the absence of memory-corruption vulnerabilities in the desktop/webview, OS keychain, Rust compiler/runtime, kernel, drivers, or native dependencies.

**Recommended paper edit:** replace “elimina essa classe de erros” with “elimina, no código Rust próprio auditado, classes de corrupção de memória; dependências nativas, WebView e sistema operacional permanecem fora dessa garantia.”

### 1.2 Key zeroization exists for long-lived master keys, but is not a whole-process secrecy proof

**Verdict: PARTIAL. Severity: Tier-2 major.**

`MasterKey` derives `Zeroize` and `ZeroizeOnDrop` (`crates/sv-crypto/src/lib.rs:78-82`), and `Vault` owns its DEKs as `MasterKey`s (`crates/sv-storage/src/lib.rs:232-243`). `AuditLog` also wipes its copied HMAC key on drop (`crates/sv-audit/src/lib.rs:398-411`). This supports the narrower statement that principal in-memory key objects are cleared on normal drop.

It does not establish that every temporary key/plaintext copy is zeroized: `open` returns a plain `Vec<u8>` (`crates/sv-crypto/src/lib.rs:175-194`), transit decryption returns a `Vec<u8>` (`crates/sv-core/src/transit.rs:317-330`), and the MCP response base64-encodes plaintext for the agent (`crates/sv-mcp/src/lib.rs:1723-1727`). No OS memory locking, anti-swap, core-dump suppression, allocator scrubbing, or process hardening is implemented here.

**Recommended paper edit:** say “chaves mestras de longa duração usam zeroização no descarte”; do not claim full memory erasure or protection against same-user memory scraping.

### 1.3 Tauri is used, but comparative injection-surface and independent-sandbox claims are untested

**Verdict: UNSUPPORTED. Severity: Tier-2 major.**

The app is a Tauri 2 shell (`apps/desktop/src-tauri/Cargo.toml:25-27`) with a restrictive CSP (`apps/desktop/src-tauri/tauri.conf.json:24-26`) and a small declared Tauri capability set (`apps/desktop/src-tauri/capabilities/default.json:1-9`). Markdown preview is sanitized before Svelte’s HTML insertion (`ui/src/components/FileViewerModal.svelte:42-45,205`). Those are positive implementation facts. The repository contains no Electron comparison, threat experiment, sandbox configuration proving an independent Rust/WebView security boundary, or injection-rate measurement. The paper’s §3.8 conclusion that Tauri’s architecture “minimiz[es] a superfície” is consequently an architectural expectation, not artifact evidence.

**Recommended paper edit:** describe Tauri as the chosen UI runtime with CSP/capability restrictions, and remove the comparative “minimiza” conclusion unless it is backed by a separate measured or literature-grounded comparison.

### 1.4 RQ3 conflates language safety with OS-level isolation; the artifact does not provide OS process isolation

**Verdict: UNSUPPORTED. Severity: Tier-1 blocking.**

RQ3 asks about “isolamento de memória no nível do sistema operacional” (paper §1.3). The running desktop constructs the MCP server in the same application process and passes it the same shared `VaultHandle` (`apps/desktop/src-tauri/src/lib.rs:1626-1658`); it binds a loopback socket, not a separate sandboxed vault process (`apps/desktop/src-tauri/src/lib.rs:1616-1624`). Storage makes directories `0700` and files `0600` only on Unix; non-Unix implementations are explicit no-ops (`crates/sv-storage/src/lib.rs:950-1015`). These are same-account file permissions, not separate processes, users, namespaces, MAC policies, VMs, TEEs, or memory-protection domains.

The existing threat model is correctly narrower: it puts “the local OS user account + OS keychain” inside the trusted zone (`docs/threat-model.md:29-35`) and documents same-user/local-malware residual risk. Thus Rust safety, loopback binding, scopes, and consent are *application-layer controls*. They cannot answer an OS-memory-isolation RQ or mitigate a malicious process with the user’s authority that can inspect memory, retrieve the pairing secret, or act through local IPC.

**Recommended paper edit:** replace RQ3 with “Como autenticação local, escopos, consentimento e auditoria reduzem acessos laterais por agentes MCP comprometidos dentro do modelo de ameaça de usuário único?” If OS isolation is retained, add and evaluate a real boundary (separate service account/process plus OS enforcement) before claiming it.

## 2. Local vault (§3.6.1)

### 2.1 Authenticated encrypted storage and a KEK/DEK hierarchy are implemented

**Verdict: SUPPORTED. Severity: Tier-3 minor.**

Files are encrypted with XChaCha20-Poly1305 using a fresh 24-byte nonce and caller-supplied AAD (`crates/sv-crypto/src/lib.rs:149-193`). Storage writes a versioned envelope and binds `container/file_name` as AAD, so a ciphertext moved to another logical path fails authentication (`crates/sv-storage/src/lib.rs:509-535,538-567,640-642`). Passphrase custody derives a KEK using Argon2id v1.3 with the crate defaults (`crates/sv-crypto/src/lib.rs:92-103`), and `VaultHandle` derives that KEK from persisted salt (`crates/sv-core/src/lib.rs:1912-1915`). The keyring wraps DEK version(s) under the KEK (`crates/sv-core/src/keyring.rs:206-218,260-282`).

**Recommended paper edit:** name the actual construction: “XChaCha20-Poly1305 com AAD de caminho lógico; KEK derivada por Argon2id e usada para envolver DEKs versionadas.”

### 2.2 “Per-container permissions” means policy labels, not per-container cryptographic or OS isolation

**Verdict: PARTIAL. Severity: Tier-2 major.**

Each container receives a manifest rule `<name>/** → SecurityMode` (`crates/sv-storage/src/lib.rs:419-454`), and mode lookup uses that rule (`crates/sv-storage/src/lib.rs:376-387`). This is a useful *logical policy label*. The storage crate expressly does not enforce HITL (`crates/sv-storage/src/lib.rs:99-104`); enforcement is later in MCP/desktop. Every container’s files are encrypted using the vault’s currently active DEK (`crates/sv-storage/src/lib.rs:520-535`), not an independent per-container key. Therefore a process holding the open vault handle has cryptographic access across containers; container policy is not a cryptographic compartment.

Unix permissions protect the vault directory and encrypted files from *other OS users* (`crates/sv-storage/src/lib.rs:981-1010`), but do not distinguish containers and are not implemented on non-Unix (`crates/sv-storage/src/lib.rs:994-1015`). Logical names, rules/descriptions, encrypted sizes, and timestamps remain visible in the filesystem/manifest model (`crates/sv-storage/src/lib.rs:163-188,217-230`).

**Recommended paper edit:** change “permissões por contêiner” to “políticas lógicas por contêiner, aplicadas pelo gateway após desbloqueio”; state explicitly that v1 does not implement per-container keys or OS ACL compartments.

## 3. MCP gateway (§3.6.2)

### 3.1 The actual tool surface is broader than the traceability document reports

**Verdict: SUPPORTED for existence; Tier-2 major for documentation drift.**

The descriptors expose 17 base tools: `vault.list`, `read`, `write`, `delete`, `create_container`, `destroy`, `info`, `export_agents`, `import_agents`, `create_transit_key`, `list_transit_keys`, `encrypt`, `decrypt`, `create_signing_key`, `list_signing_keys`, `sign`, and `verify` (`crates/sv-mcp/src/lib.rs:2232-2449`), plus three broker tools when broker support is enabled: `broker_request`, `create_broker_secret`, `list_broker_secrets` (`crates/sv-mcp/src/lib.rs:2152-2219`), for 20 tools in that configuration. The `AccessAction` enum confirms that these are security-relevant actions (`crates/sv-mcp/src/lib.rs:391-437`). `docs/thesis/TRACEABILITY.md:44` still says “15 tools,” which is stale.

**Recommended paper edit:** enumerate the tools or report “17 base tools; 3 broker tools conditional on feature/configuration (20 total when enabled),” and correct the traceability count.

### 3.2 `call_tool` is the normal gateway pipeline, but `enforce_scopes` is not a universal choke point

**Verdict: PARTIAL. Severity: Tier-1 blocking.**

For a normal paired WebSocket request, `call_tool` builds one normalized request, calls `enforce_scopes`, invokes the access controller, writes an attempted audit event, executes, filters anonymized reads, then records outcome (`crates/sv-mcp/src/lib.rs:1007-1156`). This is the primary enforcement pipeline. `enforce_scopes` itself correctly evaluates matching container/action/mode ceilings for a populated scoped agent (`crates/sv-mcp/src/lib.rs:1850-1910`).

However, an empty scope list is deliberately treated as full access (`crates/sv-mcp/src/lib.rs:1854-1857`). The internal stdio server starts every request as `AlreadyPaired(None)`, therefore without an identity/scope check (`crates/sv-mcp/src/lib.rs:721-739`). More seriously, the production headless `serve` authenticator authenticates a registered agent but discards `a.scopes` and returns `scopes: Vec::new()` (`apps/cli/src/serve.rs:227-253`). Hence **every paired agent becomes unscoped in headless mode**. This is a concrete bypass of per-agent least privilege, not just a caveat. It is not covered in `docs/SECURITY-REVIEW.md`, which tests the desktop/live gateway path.

**Recommended paper edit:** do not describe `enforce_scopes` as a single universal choke point. Qualify the current validated claim to desktop WebSocket requests, and list headless scope preservation as a blocking implementation limitation/future fix before claiming gateway-wide least privilege.

## 4. Privacy mediation (§3.6.3)

### 4.1 Transit and signing keys exist and their raw key material is not returned by the documented MCP operations

**Verdict: SUPPORTED. Severity: Tier-3 minor.**

Transit keys are generated, wrapped under a material wrapping key, and only metadata is listed (`crates/sv-core/src/transit.rs:245-279`). Transit encrypt/decrypt unwrap internally and return ciphertext/plaintext, not the key (`crates/sv-core/src/transit.rs:282-330`). Signing creates an Ed25519 keypair, stores only the public key in cleartext and the private seed encrypted under the wrapping key (`crates/sv-core/src/transit.rs:368-392`); signing returns a signature and public key (`crates/sv-mcp/src/lib.rs:1729-1740`). This supports “the private key is not returned/exposed as a tool result,” not “the operation cannot be abused.”

**Recommended paper edit:** use “a chave privada não é retornada pelo protocolo MCP; o agente recebe somente cifra, texto decifrado ou assinatura conforme a operação autorizada.”

### 4.2 Desktop mediation prevents an automatic signing/decryption oracle, but authorizes opaque arbitrary payloads; headless mode is an actual oracle path

**Verdict: RISK. Severity: Tier-1 blocking.**

In the desktop controller, all transit and signing create/list/encrypt/decrypt/sign actions require a click; only public-key `verify` is promptless (`apps/desktop/src-tauri/src/lib.rs:764-784`). Scope enforcement requires an explicitly granted action for modeless key operations (`crates/sv-mcp/src/lib.rs:1866-1887`). A malicious desktop-connected agent therefore cannot silently obtain an arbitrary signature/decryption: it needs a scope grant (if scoped) and a fresh desktop approval.

But the approval prompt data contains only action, container, file, mode, byte size, and optional OTP (`ui/src/lib/types.ts:39-47`), and the UI displays only action/container/file (`ui/src/components/ApprovalModal.svelte:29-42`). `key_ref`, payload/ciphertext identity, recipient, plaintext risk, and an understandable payload digest are absent. The authorization context cryptographically binds exact JSON arguments (`crates/sv-mcp/src/lib.rs:489-496`), which prevents a post-approval swap, but it is not presented to the human. Thus the human approves “Sign” or “Decrypt” without enough information to decide whether the arbitrary request is legitimate.

The headless controller only rejects actions having a protected container mode; it returns `Ok` for modeless transit/sign/decrypt/broker actions (`apps/cli/src/serve.rs:188-208`). Combined with its scope-dropping bug above, a paired malicious agent in `serve` mode can request arbitrary signing and decryption operations without consent. Key bytes still remain secret, but this is precisely a signature/decryption oracle.

**Recommended paper edit:** replace the absolute safety claim with a conditional claim limited to the desktop controller, disclose that approval is per operation but not payload-transparent, and exclude headless operation from any “human-mediated private-key use” result until fixed.

### 4.3 PII coverage is narrow and heuristic; Brazilian RG, CEP, full names, addresses, and bare phones are not covered

**Verdict: PARTIAL. Severity: Tier-1 blocking if the paper implies general LGPD/PII masking.**

`sv-privacy` detects exactly seven categories: email, CPF, CNPJ, Luhn-valid payment card, IPv4, conservatively formatted phone, and US SSN (`crates/sv-privacy/src/lib.rs:46-77,205-232`). CPF/CNPJ permit formatted or bare digits but require checksum validation (`crates/sv-privacy/src/lib.rs:417-452`); cards require Luhn (`crates/sv-privacy/src/lib.rs:455-478`). Phone matching only begins with `+` or `(` and admits 10–13 digits, deliberately missing bare local numbers (`crates/sv-privacy/src/lib.rs:480-520`). There is no `RG`, `CEP`, person-name, street/address, date-of-birth, Brazilian driver licence, bank account, or free-text identifier category in the enum/detector dispatch (`crates/sv-privacy/src/lib.rs:46-77,205-232`).

**Recommended paper edit:** replace generic “mascaramento de PII” with “mascaramento heurístico de e-mail, CPF, CNPJ, cartão com Luhn, IPv4, telefones formatados e SSN; RG, CEP, nomes completos, endereços e telefones não formatados não são detectados nesta versão.”

### 4.4 `ANONYMIZED` is an egress-only, read-only, UTF-8 reduction control—not anonymization of the stored container

**Verdict: PARTIAL. Severity: Tier-2 major.**

Desktop policy treats `ANONYMIZED` like `DIRECT` (no prompt) (`apps/desktop/src-tauri/src/lib.rs:786-800`). MCP only invokes the filter for `ReadFile` from that mode (`crates/sv-mcp/src/lib.rs:1159-1173`); it decodes valid UTF-8, masks using the seven-category policy, marks the response, and records a count (`crates/sv-mcp/src/lib.rs:1174-1199`). Non-UTF-8 egress is denied, rather than passed through (`crates/sv-mcp/src/lib.rs:1180-1183`). Writes, lists, signatures, broker results, ordinary `DIRECT`/`APPROVAL`/`OTP` reads, and data at rest are not redacted by this path.

**Recommended paper edit:** define the mode as “leitura automática com pseudomascaramento heurístico na saída MCP; não altera o dado em repouso e não garante anonimização nem cobertura completa de PII.”

## 5. Human-in-the-loop and audit (§3.6.4)

### 5.1 The three specified consent modes exist and work through desktop Rust + UI, with defined boundaries

**Verdict: SUPPORTED for desktop runtime; PARTIAL artifact-wide. Severity: Tier-2 major.**

`SecurityMode` defines `Direct`, `Approval`, and `Otp` (`crates/sv-storage/src/lib.rs:107-120`). Desktop policy makes DIRECT promptless, APPROVAL a click, and OTP a cross-channel code (`apps/desktop/src-tauri/src/lib.rs:786-805`). Approval waits for an approved Tauri event and times out/denies otherwise (`apps/desktop/src-tauri/src/lib.rs:449-515`); the Svelte app receives the event and renders the approval/OTP surfaces (`ui/src/App.svelte:43-54,88-99`). OTP is six digits from OS randomness (`apps/desktop/src-tauri/src/lib.rs:238-244`), bound to the request signature, single-use, and expires/locks out after failures (`apps/desktop/src-tauri/src/lib.rs:274-408`; `ui/src/components/OtpModal.svelte:18-30`).

The qualification is important: DIRECT has no prompt by design, `ANONYMIZED` also has no prompt, and `ZKP`/`NATIVE` are rejected as unimplemented for live MCP (`apps/desktop/src-tauri/src/lib.rs:786-805`). The headless gateway deliberately has no UI and rejects protected container modes, but (as above) permits mode-less sensitive operations (`apps/cli/src/serve.rs:188-208`). Therefore the three modes are end-to-end for the desktop container access path, not a general proof that all artifact operations always have human mediation.

**Recommended paper edit:** say “a implementação desktop oferece três modos de consentimento para operações de contêiner; operações DIRETAS não solicitam confirmação e o modo headless não fornece essa garantia.”

### 5.2 The audit log is HMAC-chained and fail-closed on detected changes, but it is not append-only against rollback and lacks an external trust anchor

**Verdict: PARTIAL. Severity: Tier-1 blocking if paper says simply “append-only/hash-chained.”**

Each record contains sequence, previous MAC, event, and a domain-separated HMAC-SHA256 (`crates/sv-audit/src/lib.rs:977-1056`). Appending fsyncs the record before writing a signed checkpoint (`crates/sv-audit/src/lib.rs:545-617`); opening verifies archives and the checkpoint before use (`crates/sv-audit/src/lib.rs:458-485`), and `verify_chain` verifies record count/head against the checkpoint (`crates/sv-audit/src/lib.rs:647-727`). This supports tamper *evidence* against alteration, deletion, and truncation relative to the currently stored checkpoint.

It is not immutable append-only storage. An attacker able to restore the entire vault/audit directory, including a prior valid checkpoint, restores a valid HMAC chain. The key is deterministically derived from the identity root (`crates/sv-core/src/lib.rs:713-719`), which itself is local vault/key-custody material; no remote transparency log, hardware monotonic counter, separate OS keychain anchor, or external witness is written by `sv-audit`. This limitation is already candidly stated in `docs/SECURITY-REVIEW.md` Scenario E and `docs/threat-model.md` §4; it must move into the paper.

**Recommended paper edit:** replace “logs append-only encadeados por hash” with “logs HMAC-SHA256 encadeados e verificados contra checkpoint local; detectam adulteração/truncamento, mas não rollback completo sem âncora externa.”

## 6. Latency model and observed measurements (§3.9.1)

### 6.1 Equation 1 is not a fixed additive artifact latency; it mixes different populations and unmeasured external terms

**Verdict: UNSUPPORTED as written. Severity: Tier-1 blocking.**

The gateway itself documents that it observes only validation, authorization, execution, and filtering; WAN and inference are external (`crates/sv-mcp/src/lib.rs:550-587`). It calculates the emitted `total` as only `validate + authorize + execute + filter` (`crates/sv-mcp/src/lib.rs:1202-1225`). Therefore `T_rede + T_inferência` cannot be attributed to, or measured by, this artifact. Adding them to a measured gateway total also risks double counting: depending on where timing starts/stops, a cloud round trip may already include client serialization, MCP response transfer, and model work; the paper supplies no operational boundary for the five terms.

Most importantly, `T_aprovação` is human waiting time—unbounded, behavioral, non-deterministic, and only present for APPROVAL/OTP actions. DIRECT and ANONYMIZED return immediately (`apps/desktop/src-tauri/src/lib.rs:786-800`). The harness replaces the human with `AutoAllow` (`apps/thesis-eval/src/main.rs:123-138`), so its `authorize` result is dispatch overhead, not human approval time. The harness’s own output says exactly this (`target/thesis-eval/latency.md:18`). Treating that number as a universal fixed additive term makes a modelled human workflow look microsecond-fast when a real approval can take seconds, minutes, or never occur.

**Recommended paper edit:** replace Equation 1 with a conditional decomposition: `T_gateway = T_parse+validate+scope + T_vault + T_redact(if ANONYMIZED) + T_consent(mode)`; report `T_consent` separately as a distribution for APPROVAL/OTP, and report cloud `T_wan+inferência` only in a separately instrumented end-to-end experiment.

### 6.2 What the latency harness actually measures, and what the checked-in CSV represents

**Verdict: PARTIAL. Severity: Tier-2 major.**

The harness creates a throwaway passphrase vault in a temp directory (`apps/thesis-eval/src/main.rs:98-117`), seeds four synthetic containers and three synthetic payload sizes (128 B, 1 KiB, 16 KiB) (`apps/thesis-eval/src/main.rs:407-474`), then drives `vault.read` through the real **stdio** gateway with `AutoAllow` (`apps/thesis-eval/src/main.rs:431-501`). It is a single-machine microbenchmark of a synthetic local read path—not a user study, not a production workload, not a cloud comparison, and not a measurement of a live external model. Default `N` is 200 (`apps/thesis-eval/src/main.rs:57-85`); the checked-in `target/thesis-eval/latency.csv` reports `iterations=1000` in every cell (`target/thesis-eval/latency.csv:1-61`), so the present data are 12 cells × 1,000 reads.

The output is generated by live Rust timing code, not a hand-authored table: it writes the CSV from collected `StageTimings` (`apps/thesis-eval/src/main.rs:513-564`). It is still synthetic experimental input. The output files contain no machine-readable CPU/OS/rustc/command/commit provenance; their filesystem timestamps alone are not a reproducibility record. Existing `docs/thesis/EVALUATION.md:16-18,79-95` supplies narrative host context but it does not bind it cryptographically to the current files.

Present Linux-target numbers (`target/thesis-eval/latency.md:7-18`) are: DIRECT mean 14.70 µs (128 B), 17.77 µs (1 KiB), 36.64 µs (16 KiB); APPROVAL 13.93/15.36/34.41 µs; OTP 13.57/15.62/35.23 µs; ANONYMIZED 15.74/26.07/189.79 µs. These are gateway-stage numbers with auto-allow, not end-to-end user latency. The claimed “sub-millisecond” result is true for this synthetic local path, but not for human-gated or cloud inference transactions.

**Recommended paper edit:** label the table “microbenchmark de gateway local, N=1.000 por célula, AutoAllow, dados sintéticos”; add complete run provenance and prohibit it from supporting end-to-end/cloud latency claims.

## 7. Adversarial evaluation (§3.9.2)

### 7.1 The 100% rate is a finite scripted request battery, not a prompt-injection efficacy estimate

**Verdict: PARTIAL. Severity: Tier-1 blocking.**

The harness calls the real authenticated loopback WebSocket gateway (`apps/thesis-eval/src/main.rs:657-680,818-862`), so it exercises real pairing, request parsing, scopes, storage validation, and the harness `HitlPolicy`. That is stronger than a unit-test mock. But the “attacker prompt” is not generated or sent to a model: a static vector of exactly ten pre-authored JSON-RPC attacks (A1–A10) and two controls (C1–C2) is constructed in source (`apps/thesis-eval/src/main.rs:682-780`). “Blocked” means a JSON-RPC/tool result error; transport or pairing errors are also counted as blocks (`apps/thesis-eval/src/main.rs:789-804,857-862`). There is one execution of each probe, no random sampling, no repeated independent runs, no confidence interval, and no adaptive attacker.

The checked-in output correctly says 10/10 attacks blocked (100.0%) and 2/2 controls allowed (100.0%) (`target/thesis-eval/adversarial.md:3-18`; `target/thesis-eval/adversarial.csv:1-13`). This is coverage of a narrow modelled set: out-of-scope reads/writes/deletes, two traversal spellings, enumeration, absent consent, and NATIVE rejection. It does not cover semantic prompt attacks, data-flow exfiltration through allowed DIRECT reads, PII recall, signing/decryption-oracle abuse, headless scope loss, tool-schema fuzzing, token theft, same-user malware, or a model that adapts after seeing errors. The existing evaluation document already calls it a finite threat-set coverage claim (`docs/thesis/EVALUATION.md:176-178`); the paper must do the same.

**Recommended paper edit:** report “10/10 pre-specified gateway probes were blocked in one black-box execution” and remove any inference that this is a general prompt-injection block rate or privacy-resilience percentage.

## 8. Evaluation design and traceability

### 8.1 Objective 4 promises a cloud comparison that neither paper plan nor harness contains

**Verdict: UNSUPPORTED. Severity: Tier-1 blocking.**

Objective 4 promises effectiveness “em comparação com modelos tradicionais em nuvem” (paper §1.4.2). The harness has only `latency`, `micro`, and `adversarial` subcommands (`apps/thesis-eval/src/main.rs:71-79`); it creates a local temporary vault and external network/inference legs are explicitly excluded from its latency output (`apps/thesis-eval/src/main.rs:533-562`). No cloud model/API client, baseline condition, prompt corpus, cost, retention policy, model/version pinning, or equivalence check exists. `docs/thesis/TRACEABILITY.md:47` marks this objective complete, but that conclusion is contradicted by the harness.

A defensible two-arm evaluation requires at minimum: (1) the same task/prompt and same source data under **A: local gateway** and **B: cloud-direct**; (2) pre-registered outcomes—end-to-end latency, successful unauthorized disclosure, PII recall/precision, task utility, cost, and failures; (3) fixed model/version/region/network and repeated paired runs; (4) an ethics/consent/data-handling plan using synthetic or approved non-sensitive data; and (5) a defined baseline policy (cloud direct must genuinely receive the material the local gateway withholds). The current harness can be extended for Arm A but cannot perform Arm B without a new client/adapter, credentials, controlled corpus, timing boundaries, telemetry and statistical analysis.

**Recommended paper edit:** either remove “em comparação com modelos tradicionais em nuvem” from Objective 4, or add a new two-arm protocol and present it as future evaluation—not as completed evidence.

### 8.2 RQ ↔ objective ↔ artifact gaps

**Verdict: PARTIAL. Severity: Tier-1 blocking.**

The artifact is explicitly a secrets/credentials instantiation, not a context/RAG system (`docs/thesis/TRACEABILITY.md:13-17`; `docs/adr/0012-context-containers.md:10-18`). It has point file reads; it has no implemented vector index, local embedding model, document search tool, or cloud statelessness enforcement. Thus RQ1’s “consultas contextuais” is only partially instantiated by named secret-file access. RQ2 is answered only for internal synthetic gateway stages. RQ3 is not answered because its OS-isolation construct is absent. Objective 4’s cloud comparator is absent. `TRACEABILITY.md` currently overstates these gaps by treating all as complete (`docs/thesis/TRACEABILITY.md:44-55`).

The paper can defensibly claim a DSR instantiation for local secret/credential mediation, scoped agent access, consent modes, audit integrity, and limited egress masking. It cannot yet claim an evaluated general architecture for personal context, RAG, stateless cloud inference, OS-level memory isolation, comprehensive PII protection, or cloud-vs-local performance/security superiority.

**Recommended paper edit:** add a scope box in Chapters 1 and 3: “A instância avaliada limita-se a credenciais/segredos nomeados em uma máquina e ao gateway local; RAG, busca vetorial, isolamento de processo/OS e comparação com nuvem são trabalho futuro.”

## New issues not already surfaced by `SECURITY-REVIEW.md`

1. **Headless scope erasure (Tier-1).** `HeadlessAuthenticator` authenticates but returns `Vec::new()` instead of the persisted agent scopes (`apps/cli/src/serve.rs:227-253`); `enforce_scopes` turns empty scopes into full access (`crates/sv-mcp/src/lib.rs:1854-1857`). This invalidates a gateway-wide least-privilege claim.
2. **Headless modeless crypto/broker approval bypass (Tier-1).** `HeadlessAccessController` gates only `request.mode` and permits `None` (`apps/cli/src/serve.rs:188-208`), while transit/sign/decrypt/broker requests have no mode (`crates/sv-mcp/src/lib.rs:1433-1520`). It creates unmediated decryption/signature oracle capability for any paired agent in that deployment mode.
3. **Opaque desktop crypto consent (Tier-2).** Exact request binding exists (`crates/sv-mcp/src/lib.rs:489-496`), but users are not shown key reference or payload identity (`ui/src/lib/types.ts:39-47`; `ui/src/components/ApprovalModal.svelte:29-42`). This makes “human approval” weak evidence of meaningful informed consent for signatures/decryptions.
